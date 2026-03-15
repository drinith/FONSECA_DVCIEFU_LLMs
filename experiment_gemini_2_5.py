import os
from dotenv import load_dotenv
import google.generativeai as genai
from func_timeout import func_set_timeout
import func_timeout


# Carrega as variáveis do arquivo .env para o ambiente do sistema
load_dotenv()

# Busca a chave usando o nome definido no .env
api_key = os.environ.get("GOOGLE_API_KEY")

if not api_key:
    raise ValueError("Erro: GOOGLE_API_KEY não encontrada no arquivo .env")

genai.configure(api_key=api_key)

# Cria o modelo
model = genai.GenerativeModel('gemini-2.5-flash')

# Lista de arquivos já processados
xx = os.listdir("./results_gemini_teste/")
xxx = [i[:-4] + '.sol' for i in xx]
filenames = list(set(os.listdir("./smartbugs-curated/dataset/processed")) - set(xxx))
position_file = 0
error_cnt = 0

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

@func_set_timeout(100)
def generate_answer(messages):
    response = model.generate_content(messages)
    return response.text.strip()

# Loop pelos arquivos não processados
while position_file < len(filenames):
    filename = filenames[position_file]
    print(filename)
    
    try:
        with open("./smartbugs-curated/dataset/processed/" + filename, 'r', encoding='utf-8') as f:
            codes = f.read()
        
        codes_processed = preprocess(codes)

        prompt = (
            "You are a vulnerability detector for a smart contract. Here are nine common vulnerabilities:\n"
            "1. Reentrancy: race to empty, recursive call, call to the unknown\n"
            "2. Access Control\n"
            "3. Arithmetic Issues: integer overflow/underflow\n"
            "4. Unchecked Return Values For Low Level Calls: silent failing sends\n"
            "5. Denial of Service: gas limit, unexpected throw/kill, access breach\n"
            "6. Bad Randomness: nothing is secret\n"
            "7. Front-Running: TOCTOU, race condition, TOD\n"
            "8. Time Manipulation: timestamp dependence\n"
            "9. Short Address Attack: off-chain issues, client vulnerabilities\n\n"
            "Think step by step, carefully. Check the following smart contract for the above vulnerabilities:\n\n"
            f"{codes_processed}"
        )

        res = generate_answer(prompt)

    except func_timeout.exceptions.FunctionTimedOut:
        print("timeout")
    except Exception as e:
        print("error:", e)
        position_file += 1
        continue
    else:
        print("success, outputting...")
        with open('./results_gemini_teste/' + filename[:-4] + '.txt', 'w') as f:
            f.write(res)
        position_file += 1