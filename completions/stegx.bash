
_stegx()
{
    local cur prev words cword
    _init_completion || return

    local subcommands="encode decode shamir-split shamir-combine benchmark --help --version"

    local global_opts="-v --version --verbose -h --help"
    local encode_opts="\
        -i --image -f --file -o --output \
        -p --password --password-stdin --keyfile \
        --kdf --dual-cipher --adaptive --adaptive-cutoff --matrix-embedding \
        --max-fill --strict-password --no-preserve-cover --no-compress \
        --compression --decoy-file --decoy-password -h --help"
    local decode_opts="\
        -i --image -d --destination --stdout \
        -p --password --password-stdin --keyfile -h --help"
    local shamir_split_opts="\
        -k -n -f --file -c --cover -O --out-dir \
        -p --password --password-stdin --keyfile \
        --kdf --dual-cipher --adaptive --adaptive-cutoff --matrix-embedding \
        --max-fill --strict-password --no-preserve-cover --no-compress \
        --compression -h --help"
    local shamir_combine_opts="\
        -i --image -d --destination -o --output \
        -p --password --password-stdin --keyfile -h --help"
    local benchmark_opts="--iterations --size-kib -h --help"

    local sub=""
    local i
    for (( i=1; i < cword; i++ )); do
        case "${words[i]}" in
            encode|decode|shamir-split|shamir-combine|benchmark)
                sub="${words[i]}"
                break
                ;;
        esac
    done

    if [[ -z "$sub" ]]; then
        COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )
        return 0
    fi

    case "$prev" in
        -i|--image|-f|--file|-o|--output|-c|--cover|--keyfile|--decoy-file)
            _filedir
            return 0
            ;;
        -d|--destination|-O|--out-dir)
            _filedir -d
            return 0
            ;;
        --kdf)
            COMPREPLY=( $(compgen -W "argon2id pbkdf2" -- "$cur") )
            return 0
            ;;
        --compression)
            COMPREPLY=( $(compgen -W "fast best" -- "$cur") )
            return 0
            ;;
        --max-fill|--adaptive-cutoff|--iterations|--size-kib|-k|-n)
            return 0
            ;;
        -p|--password|--decoy-password)
            return 0
            ;;
    esac

    local opts="$global_opts"
    case "$sub" in
        encode)         opts="$encode_opts" ;;
        decode)         opts="$decode_opts" ;;
        shamir-split)   opts="$shamir_split_opts" ;;
        shamir-combine) opts="$shamir_combine_opts" ;;
        benchmark)      opts="$benchmark_opts" ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    else
        _filedir
    fi
}

complete -F _stegx stegx
