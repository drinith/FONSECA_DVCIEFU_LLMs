import os

def preprocess(text):
    l = [
        'vulnerable_at_lines:',
        '// <yes> <report> DENIAL_OF_SERVICE',
        '// <yes> <report> ARITHMETIC',
        '// <yes> <report> BAD_RANDOMNESS',
        '// <yes> <report> ACCESS_CONTROL',
        '// <yes> <report> FRONT_RUNNING',
        '// <yes> <report> REENTRANCY',
        '// <yes> <report> SHORT_ADDRESSES',
        '// <yes> <report> TIME_MANIPULATION',
        '// <yes> <report> UNCHECKED_LL_CALLS'
    ]
    for i in l:
        text = text.replace(i, '')
    return text


filenames = os.listdir("./smartbugs-curated/dataset/all")
position_file = 0

while position_file < len(filenames):
    filename = filenames[position_file]
    print(filename)

    try:
        with open("../smartbugs-curated/dataset/all/" + filename, 'r', encoding='utf-8') as f:
            codes = f.read()

        codes_processed = preprocess(codes)

        print("=" * 60)
        print("ANTES:")
        print(codes[:500])  # primeiros 500 chars pra não poluir o terminal
        print("=" * 60)
        print("DEPOIS:")
        print(codes_processed[:500])
        print("=" * 60)

        # Verifica se algum marcador sobrou
        markers = [
            'vulnerable_at_lines:',
            '// <yes> <report> DENIAL_OF_SERVICE',
            '// <yes> <report> ARITHMETIC',
            '// <yes> <report> BAD_RANDOMNESS',
            '// <yes> <report> ACCESS_CONTROL',
            '// <yes> <report> FRONT_RUNNING',
            '// <yes> <report> REENTRANCY',
            '// <yes> <report> SHORT_ADDRESSES',
            '// <yes> <report> TIME_MANIPULATION',
            '// <yes> <report> UNCHECKED_LL_CALLS'
        ]
        all_ok = True
        for m in markers:
            if m in codes_processed:
                print(f"  ✗ AINDA PRESENTE: {m!r}")
                all_ok = False
        if all_ok:
            print("✅ preprocess OK")
        else:
            print("❌ FALHA no preprocess")

    except Exception as e:
        print("erro:", e)

    position_file += 1