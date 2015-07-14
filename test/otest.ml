open Lwt.Infix

let char_hex n =
  Char.unsafe_chr (n + if n < 10 then Char.code '0' else (Char.code 'a' - 10))

let to_hex orig =
  let orig_len = Bytes.length orig in
  let res_len = if orig_len mod 2 = 0 then orig_len * 2 else orig_len*2 + 1 in
  let result = Bytes.create res_len in
  for i = 0 to orig_len - 1 do
    let x = Bytes.get orig i |> Char.code in
    Bytes.set result (i*2) (char_hex (x lsr 4));
    Bytes.set result (i*2+1) (char_hex (x land 0x0f));
  done;
  Bytes.unsafe_to_string result


module R = Uwt_random

let with_random f =
  R.init () >>= fun t ->
  Lwt.finalize
    ( fun () -> f t )
    ( fun () -> R.close t )

let t () =
  (* print something nice on stdout *)
  let t = with_random ( fun t ->
      let buf = Bytes.init 32 ( fun _ -> Char.chr 0) in
      let rec iter i =
        if i < 0 then
          Lwt.return_unit
        else
          R.get ~buf t >>= fun () ->
          to_hex buf |> Uwt_io.printl >>= fun () ->
          iter (pred i)
      in
      iter 4
    )
  in
  Uwt.Main.run t

let () =
  t ();
  t ();
  t ()

open OUnit2

let run = Uwt.Main.run

module type Bytes_type = sig
  type t
  val init : int  -> ( int -> char ) -> t
  val fill : t -> int -> int -> char -> unit
  val get_random : ?pos:int -> ?len:int -> buf:t -> Uwt_random.t -> unit Lwt.t
  val get : t -> int -> char
  val name : string
  val length: t -> int
end

let tests = ref []
let add_t l = tests := l ::!tests

module MakeTest (B: Bytes_type) =
struct
  (* TODO: better check, it doesn't matter if we fail 1% of the time ,... *)
  let check ?(pos=0) ?len b =
    let len = match len with
    | None -> B.length b
    | Some l -> l
    in
    let rec iter accu i =
      if i = len then
        if accu = 0 then
          false
        else
          true
      else
        let n = B.get b (i+pos) |> Char.code in
        iter (accu lor n) (succ i)
    in
    if len < 1 then
      failwith "invalid length";
    iter 0 pos

  let name s =
    String.capitalize B.name ^ "_" ^ s

  let tcheck b =
    check b |> assert_equal true

  let ncheck b =
    check b |> assert_equal false

  let () =
    (name "simple")>::
    (fun _oc ->
       let len = 32 in
       let buf = B.init len ( fun _ -> '\000') in
       let t = with_random ( fun t ->
           let rec iter i =
             B.fill buf 0 len '\000';
             assert_equal false (check buf);
             if i < 0 then
               Uwt.Main.yield () >>= fun () ->
               Lwt.return_true
             else
               B.get_random ~buf t >>= fun () ->
               tcheck buf;
               iter (pred i)
           in
           iter 3
         )
       in
       run t |> assert_equal true )
    |> add_t ;

    (name "subrange")>::
    (fun _oc ->
       with_random ( fun t ->
         let len = 32 in
         let buf = B.init len ( fun _ -> '\000') in
         let spos= 8 in
         let slen = 12 in
         B.get_random ~pos:spos ~len:slen ~buf t >>= fun () ->
         tcheck buf;
         B.fill buf spos slen '\000';
         ncheck buf;
         Lwt.return_true
         )
       |> run |> assert_equal true )
    |> add_t
end

module Bytes_test =
  MakeTest(struct
    type t = Bytes.t
    let init = Bytes.init
    let fill = Bytes.fill
    let get_random = Uwt_random.get
    let get = Bytes.get
    let length = Bytes.length
    let name = "bytes"
  end)

module Ba_test =
  MakeTest(struct
    type t = Uwt_bytes.t
    let init n f =
      let b = Uwt_bytes.create n in
      for i = 0 to pred n do
        Uwt_bytes.set b i (f i)
      done;
      b
    let fill b pos len c =
      for i = pos to pos + len - 1 do
        Uwt_bytes.set b i c;
      done
    let get_random = Uwt_random.get_ba
    let get = Uwt_bytes.get
    let length = Uwt_bytes.length
    let name = "uwt_bytes"
  end)

let tests = "All">:::(List.rev !tests)

let mexit i =
  if i <> 0 then
    prerr_endline "test case failure";
  exit i

let () =
  Unix.putenv "OUNIT_RUNNER" "sequential";
  OUnit2.run_test_tt_main ~exit:mexit tests |> ignore
