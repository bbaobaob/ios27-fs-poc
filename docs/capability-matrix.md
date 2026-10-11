# Filesystem capability matrix

## Format

One row per investigation target, one column per operation. Every cell is recorded **independently**
— a successful read is never inferred to prove enumeration capability, and a successful write in the
app container is never inferred to prove write access elsewhere.

| Column | Syscall | What it exercises |
| --- | --- | --- |
| `lstat` | `lstat()` | metadata without following a final symlink |
| `stat` | `stat()` | metadata, following a final symlink |
| `opendir` | `opendir()` | acquiring a directory handle (search permission) |
| `readdir` | `readdir()` | listing entries (read permission on the directory) |
| `open+read` | `open(O_RDONLY)` + `read()` | reading file contents |
| `open+create` | `open(O_CREAT\|O_EXCL)` | creating a new file in the target directory |
| `open+write` | `open(O_WRONLY\|O_CREAT\|O_TRUNC)` + `write()` | modifying a file in the target directory |
| `unlink` | `unlink()` | removing a file |
| `readlink` | `readlink()` | resolving a symbolic link |

Cell values: `succeeded`, `deniedEPERM`, `deniedEACCES`, `notFound`, `notDirectory`,
`failedOther`.

Write probes operate on the synthetic file `fsprobe-writetest.tmp` **inside** the target directory,
verify by read-back, and remove it. They never overwrite a pre-existing file.

## Host result — verification host (NOT iOS)

Platform: Swift 6.4 verification host (Android/Termux), captured by CI-equivalent local run.
**These are not iOS device results.** They exist to prove the harness runs end-to-end and reports
absence as absence rather than denial.

```
path                                       lstat        stat         opendir      readdir      open+read    open+create  open+write   unlink       readlink
---------------------------------------------------------------------------------------------------------------------------------------------------------------
<home>                                     succeeded    succeeded    succeeded    succeeded    failedOther  succeeded    succeeded    succeeded    failedOther
<home>/Documents                           notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
<home>/Library                             notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
<home>/tmp                                 succeeded    succeeded    succeeded    succeeded    failedOther  succeeded    succeeded    succeeded    failedOther
/var                                       notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/private/var                               notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile                                notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Library                        notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Library/Preferences            notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Containers                     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Containers/Data/Application    notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/mobile/Containers/Shared/AppGroup     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
/var/tmp                                   notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound     notFound
```

Notes on the host result:

- `open+read` and `readlink` on a **directory** report `failedOther` — reading a directory with
  `read()` yields `EISDIR`, and `readlink()` on a non-symlink yields `EINVAL`. This is expected and
  is recorded rather than hidden.
- Every `/var/...` path reports `notFound` (`ENOENT`) because the path does not exist on this host.
  Absence is reported as absence — never as denial.
- No discrepancies detected.

## iOS device result

**Not yet collected.** The physical iPhone run is recorded in
`docs/device-validation-log.md` with the exact iOS build, device model, signing context, per-target
errno, and reproduction count. Until that record exists, no claim is made about iOS 27 behaviour.
