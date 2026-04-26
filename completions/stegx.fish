
function __stegx_needs_subcommand
    set -l cmd (commandline -opc)
    test (count $cmd) -le 1
end

function __stegx_using_subcommand
    set -l cmd (commandline -opc)
    test (count $cmd) -ge 2; and test "$cmd[2]" = $argv[1]
end

complete -c stegx -f -n '__stegx_needs_subcommand' -a encode         -d 'Hide a file in a cover image'
complete -c stegx -f -n '__stegx_needs_subcommand' -a decode         -d 'Extract a hidden file'
complete -c stegx -f -n '__stegx_needs_subcommand' -a shamir-split   -d 'Split a secret into k-of-n stego shares'
complete -c stegx -f -n '__stegx_needs_subcommand' -a shamir-combine -d 'Recover a secret from k-or-more shares'
complete -c stegx -f -n '__stegx_needs_subcommand' -a benchmark      -d 'Measure Argon2id / compression perf'

complete -c stegx -s v -l version -d 'Show program version'
complete -c stegx -l verbose      -d 'Enable debug logging'
complete -c stegx -s h -l help    -d 'Show help'

set -l __stegx_kdf_values argon2id pbkdf2
set -l __stegx_compression_values fast best

for sub in encode shamir-split
    complete -c stegx -n "__stegx_using_subcommand $sub" -s p -l password -r      -d 'Password (discouraged)'
    complete -c stegx -n "__stegx_using_subcommand $sub" -l password-stdin         -d 'Read password from stdin'
    complete -c stegx -n "__stegx_using_subcommand $sub" -l keyfile -F             -d 'Optional keyfile (2FA)'
    complete -c stegx -n "__stegx_using_subcommand $sub" -l kdf -x -a "$__stegx_kdf_values" -d 'Password-based KDF'
    complete -c stegx -n "__stegx_using_subcommand $sub" -l dual-cipher           -d 'Layer ChaCha20-Poly1305 over AES-GCM'
    complete -c stegx -n "__stegx_using_subcommand $sub" -l adaptive              -d 'Embed only in textured regions'
    complete -c stegx -n "__stegx_using_subcommand $sub" -l adaptive-cutoff -x    -d 'Adaptive cutoff (0-1)'
    complete -c stegx -n "__stegx_using_subcommand $sub" -l matrix-embedding      -d 'F5-style matrix embedding'
    complete -c stegx -n "__stegx_using_subcommand $sub" -l max-fill -x           -d 'Refuse payloads > PCT of capacity'
    complete -c stegx -n "__stegx_using_subcommand $sub" -l strict-password       -d 'Refuse weak passwords'
    complete -c stegx -n "__stegx_using_subcommand $sub" -l no-preserve-cover     -d 'Do not match cover encoder params'
    complete -c stegx -n "__stegx_using_subcommand $sub" -l no-compress           -d 'Disable compression'
    complete -c stegx -n "__stegx_using_subcommand $sub" -l compression -x -a "$__stegx_compression_values" -d 'Compression profile'
end

complete -c stegx -n '__stegx_using_subcommand encode' -s i -l image -F  -d 'Cover image path or URL'
complete -c stegx -n '__stegx_using_subcommand encode' -s f -l file -F   -d 'File to hide'
complete -c stegx -n '__stegx_using_subcommand encode' -s o -l output -F -d 'Output stego PNG'
complete -c stegx -n '__stegx_using_subcommand encode' -l decoy-file -F        -d 'Decoy payload file'
complete -c stegx -n '__stegx_using_subcommand encode' -l decoy-password -r    -d 'Decoy password'

complete -c stegx -n '__stegx_using_subcommand decode' -s i -l image -F       -d 'Stego image'
complete -c stegx -n '__stegx_using_subcommand decode' -s d -l destination -F -d 'Output directory (or - for stdout)'
complete -c stegx -n '__stegx_using_subcommand decode' -l stdout              -d 'Write payload to stdout'
complete -c stegx -n '__stegx_using_subcommand decode' -s p -l password -r    -d 'Password'
complete -c stegx -n '__stegx_using_subcommand decode' -l password-stdin       -d 'Read password from stdin'
complete -c stegx -n '__stegx_using_subcommand decode' -l keyfile -F           -d 'Keyfile (if used)'

complete -c stegx -n '__stegx_using_subcommand shamir-split' -s k -x           -d 'Threshold'
complete -c stegx -n '__stegx_using_subcommand shamir-split' -s n -x           -d 'Total shares'
complete -c stegx -n '__stegx_using_subcommand shamir-split' -s f -l file -F   -d 'Secret file'
complete -c stegx -n '__stegx_using_subcommand shamir-split' -s c -l cover -F  -d 'Cover images'
complete -c stegx -n '__stegx_using_subcommand shamir-split' -s O -l out-dir -F -d 'Output directory'

complete -c stegx -n '__stegx_using_subcommand shamir-combine' -s i -l image -F       -d 'Stego shares'
complete -c stegx -n '__stegx_using_subcommand shamir-combine' -s d -l destination -F -d 'Output directory'
complete -c stegx -n '__stegx_using_subcommand shamir-combine' -s o -l output -r      -d 'Recovered filename'
complete -c stegx -n '__stegx_using_subcommand shamir-combine' -s p -l password -r    -d 'Password'
complete -c stegx -n '__stegx_using_subcommand shamir-combine' -l password-stdin       -d 'Read password from stdin'
complete -c stegx -n '__stegx_using_subcommand shamir-combine' -l keyfile -F           -d 'Keyfile'

complete -c stegx -n '__stegx_using_subcommand benchmark' -l iterations -x  -d 'Argon2 samples to average'
complete -c stegx -n '__stegx_using_subcommand benchmark' -l size-kib -x    -d 'Compression sample size (KiB)'
