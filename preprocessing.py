import os
import re
import argparse


def preprocess(text: str) -> str:
    """
    Remove vulnerability annotations from smart contract source code.

    Removes:
      1. Inline annotation comments such as:
             // <yes> <report> REENTRANCY
             vulnerable_at_lines: 12
      2. Header metadata blocks of the form:
             /*
              * @source: ...
              * @author: ...
              * @vulnerable_at_lines: ...
              */
    """

    # ── 1. Inline annotation markers ─────────────────────────────────────────
    inline_markers = [
        'vulnerable_at_lines:',
        '// <yes> <report> DENIAL_OF_SERVICE',
        '// <yes> <report> ARITHMETIC',
        '// <yes> <report> BAD_RANDOMNESS',
        '// <yes> <report> ACCESS_CONTROL',
        '// <yes> <report> FRONT_RUNNING',
        '// <yes> <report> REENTRANCY',
        '// <yes> <report> SHORT_ADDRESSES',
        '// <yes> <report> TIME_MANIPULATION',
        '// <yes> <report> UNCHECKED_LL_CALLS',
    ]
    for marker in inline_markers:
        text = text.replace(marker, '')

    # ── 2. Header metadata block  /*  * @source / @author / @vulnerable_at_lines  */ ──
    metadata_block_pattern = re.compile(
        r'/\*'
        r'(?:[^*]|\*(?!/))*?'
        r'@(?:source|author|vulnerable_at_lines)\s*:'
        r'(?:[^*]|\*(?!/))*?'
        r'\*/',
        re.DOTALL,
    )
    text = metadata_block_pattern.sub('', text)

    # ── 3. Tidy up: collapse 3+ consecutive blank lines into two ─────────────
    text = re.sub(r'\n{3,}', '\n\n', text)

    return text.strip()


def process_directory(input_dir: str, output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)

    sol_files = [f for f in os.listdir(input_dir) if f.endswith('.sol')]

    if not sol_files:
        print(f"Nenhum arquivo .sol encontrado em '{input_dir}'.")
        return

    print(f"Encontrados {len(sol_files)} arquivo(s) .sol em '{input_dir}'.\n")

    success, errors = 0, 0

    for filename in sorted(sol_files):
        input_path  = os.path.join(input_dir,  filename)
        output_path = os.path.join(output_dir, filename)

        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                raw = f.read()

            clean = preprocess(raw)

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(clean)

            print(f"  [OK] {filename}")
            success += 1

        except Exception as e:
            print(f"  [ERRO] {filename}: {e}")
            errors += 1

    print(f"\nConcluído: {success} processado(s), {errors} erro(s).")
    print(f"Arquivos salvos em '{output_dir}'.")


if __name__ == '__main__':
    # parser = argparse.ArgumentParser(
    #     description='Remove anotações de vulnerabilidade de arquivos .sol.'
    # )
    # parser.add_argument(
    #     'input_dir',
    #     help='Diretório contendo os arquivos .sol originais.'
    # )
    # parser.add_argument(
    #     'output_dir',
    #     help='Diretório onde os arquivos processados serão salvos.'
    # )
    # args = parser.parse_args()

    #process_directory(args.input_dir, args.output_dir)
    process_directory('./smartbugs-curated/dataset/all', './smartbugs-curated/dataset/processed')