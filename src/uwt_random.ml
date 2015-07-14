open Lwt
type ph

type noblock_init_ret =
  | Er
  (* modern linux interface blocks, if not enough
     random data is available *)
  | Eagain
  | Okey of ph
type block_init_ret =
  | I_Er
  | I_Syscall of ph
  | I_Fd of Uwt.file
type t =
  | Systok of ph
  | Fd of Uwt.file
type read_to =
  | Bytes of Bytes.t
  | Ba of Uwt_bytes.t

external noblock_init: unit -> noblock_init_ret = "uwt_random_init_nonblock"
external block_init: unit -> block_init_ret Uwt.C_worker.u -> Uwt.C_worker.t
  = "uwt_random_uwt_init"

external linux_block_init:
  unit -> block_init_ret Uwt.C_worker.u -> Uwt.C_worker.t
  = "uwt_random_uwt_linux_init"

let init_block () =
    Uwt.C_worker.call block_init () >>= function
    | I_Er -> Lwt.fail (Unix.Unix_error(Unix.ENOENT,"uwt_random_init",""))
    | I_Fd d -> return (Fd d)
    | I_Syscall d -> return (Systok d)

let init () =
  match noblock_init () with
  | Okey d -> return (Systok d)
  | Eagain ->
    Lwt.catch ( fun () ->
        Uwt.C_worker.call linux_block_init () >>= function
        | I_Er -> Lwt.fail (Unix.Unix_error(Unix.ENOENT,"uwt_random_init",""))
        | I_Fd _ -> assert false;
        | I_Syscall d -> return (Systok d)
      ) ( function
      | Unix.Unix_error _ -> init_block ()
      | x -> Lwt.fail x )
  | Er -> init_block ()

let rec uwt_iter_read fd bb ~pos ~len =
  (match bb with
  | Bytes buf -> Uwt.Fs.read ~pos ~len fd ~buf
  | Ba buf -> Uwt.Fs.read_ba ~pos ~len fd ~buf) >>= fun erg ->
  if erg >= len then
    Lwt.return_unit
  else if len > 0 then
    uwt_iter_read fd bb ~pos:(pos+erg) ~len:(len-erg)
  else
    Lwt.fail (Unix.Unix_error(Unix.EBADF,"read","/dev/urandom"))

(* file descriptor is set to O_NONBLOCK and /dev/urandom shouldn't block anyway
   For consistent error messages, I try uwt_iter_read nevertheless *)
external s_read:
  Uwt.file -> read_to -> int -> int -> int = "uwt_random_read" "noalloc"

let read fd bb ~pos ~len =
  let erg = s_read fd bb pos len in
  if erg < 0 then
    uwt_iter_read fd bb ~pos ~len
  else if erg >= len then
    Lwt.return_unit
  else
    uwt_iter_read fd bb ~pos:(pos+erg) ~len:(len-erg)

external get: ph -> read_to -> int -> int -> bool = "uwt_random_get" "noalloc"
let get_common ?(pos=0) ?len ~dim buf tok =
  let len = match len with
  | None -> dim - pos
  | Some x -> x
  in
  if len > 256 || pos < 0 || len < 0 || pos > dim - len then
    Lwt.fail (Invalid_argument "getrandom")
  else if len = 0 then
    Lwt.return_unit
  else
    match tok with
    | Fd fd -> read fd buf ~pos ~len
    | Systok t ->
      if get t buf pos len = false then
        Lwt.fail_with "invalid urandom syscall"
      else
        Lwt.return_unit

let get ?pos ?len ~buf tok =
  let dim = Bytes.length buf in
  get_common ?pos ?len ~dim (Bytes buf) tok

let get_ba ?pos ?len ~buf tok =
  let dim = Uwt_bytes.length buf in
  get_common ?pos ?len ~dim (Ba buf) tok

external close: ph -> unit = "uwt_random_close" "noalloc"
let close = function
| Fd fd -> Uwt.Fs.close fd
| Systok t ->
  if Sys.win32 then
    close t ;
  Lwt.return_unit
