open Lwt
open Nocrypto

let chunk  = 32
and period = 30

type random_source =
  | Custom of Uwt.file
  | Own of Uwt_random.t

type t = {
  fd : random_source;
  remove : (unit -> unit) Lwt_sequence.node ;
  g  : Rng.g;
}

let mvar_map v f =
  Lwt_mvar.take v >>= fun x ->
    catch (fun () -> f x >>= Lwt_mvar.put v)
          (fun exn -> Lwt_mvar.put v x >>= fun () -> fail exn)

let some x = Some x

let rec read fd ~buf ~pos ~len =
  Uwt.Fs.read_ba ~pos ~len fd ~buf >>= fun len' ->
  if len' >= len then
    Lwt.return_unit
  else
    read fd ~buf ~pos:(pos+len') ~len:(len-len')

let background ~period f =
  let last   = ref Unix.(gettimeofday ())
  and live   = ref false
  and period = float period in
  fun () ->
    let t1 = !last
    and t2 = Unix.gettimeofday () in
    if (not !live) && (t2 -. t1 >= period) then begin
      last := t2 ;
      live := true ;
      async @@ fun () -> f () >|= fun () -> live := false
    end

let attach ~period ~device g =
  Uwt.Fs.(openfile  ~mode:[O_RDONLY] device) >|= fun fd ->
  let buf = Uwt_bytes.create chunk in
  let cs = Cstruct.of_bigarray buf in
  let seed () =
    read fd ~buf ~pos:0 ~len:chunk >|= fun () -> Rng.reseed ~g cs in
  let remove =
    Lwt_sequence.add_r (background ~period seed) Uwt.Main.enter_iter_hooks
  and fd = Custom fd in
  { g ; fd ; remove }

let attach_default n g =
  Uwt_random.init () >>= fun t ->
  let buf = Uwt_bytes.create chunk in
  let cs = Cstruct.of_bigarray buf in
  let seed () = Uwt_random.get_ba ~buf t >|= fun () -> Rng.reseed ~g cs in
  let rec iter n =
    if n <= 0 then Lwt.return_unit else seed () >>= fun () -> iter (pred n)
  in
  iter n >>= fun () ->
  let remove =
    Lwt_sequence.add_r (background ~period seed) Uwt.Main.enter_iter_hooks
  and fd = Own t in
  Lwt.return { g; fd ; remove }

let stop t =
  Lwt_sequence.remove t.remove ;
  Lwt.catch ( fun () ->
      match t.fd with
      | Own fd -> Uwt_random.close fd
      | Custom fd -> Uwt.Fs.close fd
    ) (function
    | Unix.Unix_error(Unix.EBADF,_,_) -> Lwt.return_unit
    | x -> Lwt.fail x)

let active = Lwt_mvar.create None

let initialize () =
  let g = !Rng.generator in
  mvar_map active @@ function
    | Some t when t.g == g -> Lwt.return (Some t)
    | Some t              -> stop t >>= fun () -> attach_default 0 g >|= some
    | None                ->
      (* 32: magic number from upstream lwt/unix solution *)
      attach_default 32 g >|= some
