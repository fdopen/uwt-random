(**
 Uwt_random tries to obtain random data from your OS - in
 a system dependent way.
 {ul
 {- Windows: {ul {- CryptGenRandom}}}
 {- Linux:  {ul
    {- sycall with SYS_getrandom (kernel 3.17 or newer)}
    {- /dev/urandom (will fail inside chroots or if you
                    are out of file descriptors )}
    {- a deprecated SYS__sysctl syscall}}}
 {- Freebsd: {ul
    {- dedicated syscall}
    {- /dev/urandom (usually a link to /dev/random)}
    {- /dev/random (doesn't block)}}}
 {- Netbsd: {ul
    {- dedicated syscall}
    {- /dev/urandom}}}
 {- Openbsd {ul
    {- getentropy}
    {- /dev/urandom}}}
 {- Sun {ul
    {- /devices/pseudo/random@0:urandom}
    {- /dev/urandom}}}
 {- other Unix like systems: {ul {- /dev/urandom}}}}

 If several options are listed, [Uwt_random] will first try the first option,
 than the second,...
*)

type t
(** Treat it like a file descriptor. Never forgot to {!close} it *)

val init : unit -> t Lwt.t

val get : ?pos:int -> ?len:int -> buf:Bytes.t -> t -> unit Lwt.t
(** len must not be larger than 256 *)

val get_ba : ?pos:int -> ?len:int -> buf:Uwt_bytes.t -> t -> unit Lwt.t
(** len must not be larger than 256 *)

val close : t -> unit Lwt.t
