import os
from dotenv import load_dotenv
import time
import re
import google.generativeai as genai
from func_timeout import func_set_timeout
import func_timeout

# ======================
# Configurações fixas
# ======================

# Carrega as variáveis do arquivo .env para o ambiente do sistema
load_dotenv()

# Busca a chave usando o nome definido no .env
api_key = os.environ.get("GOOGLE_API_KEY")

if not api_key:
    raise ValueError("Erro: GOOGLE_API_KEY não encontrada no arquivo .env")

API_KEY = api_key
MODEL_NAME = 'gemini-1.5-flash'
TIMEOUT_SECONDS = 100
RATE_LIMIT_DELAY = 60   # fallback se não achar retry_delay
REQUEST_DELAY = 4       # delay entre chamadas para evitar rate limit
INPUT_DIR = "results_gemini_teste"
OUTPUT_DIR = "results_count_gemini_teste"

# Prompt base (sem o conteúdo ainda)
PROMPT_TEMPLATE = """You are a semantic analyzer of text. Here are nine common vulnerabilities:
1. Reentrancy: race to empty, recursive call, call to the unknown
2. Access Control
3. Arithmetic Issues: integer overflow/underflow
4. Unchecked Return Values For Low Level Calls: silent failing sends
5. Denial of Service: gas limit, unexpected throw/kill, access breach
6. Bad Randomness: nothing is secret
7. Front-Running: TOCTOU, race condition, TOD
8. Time Manipulation: timestamp dependence
9. Short Address Attack: off-chain issues, client vulnerabilities

Think step by step, carefully. The following text is a vulnerability detection result for a smart contract.
Use 0 or 1 to indicate whether there are specific types of vulnerabilities. For example: 'Reentrancy: 1'.
The input is:
{content}
"""

# ======================
# Inicializações
# ======================
genai.configure(api_key=API_KEY)
model = genai.GenerativeModel(MODEL_NAME)


@func_set_timeout(TIMEOUT_SECONDS)
def generate_answer(prompt: str) -> str:
    response = model.generate_content(prompt)
    return response.text.strip()


def process_file(filename: str):
    """Processa um único arquivo"""
    input_path = os.path.join(INPUT_DIR, filename)
    output_path = os.path.join(OUTPUT_DIR, f"{filename[:-4]}.txt")

    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()

    prompt = PROMPT_TEMPLATE.format(content=content)

    try:
        return generate_answer(prompt)
    except func_timeout.exceptions.FunctionTimedOut:
        print("⚠️ Timeout")
        return None
    except Exception as e:
        if "429" in str(e):
            print("⏳ Rate limit atingido.")
            # Extrai delay sugerido, senão usa padrão
            match = re.search(r'retry_delay\s*{\s*seconds:\s*(\d+)', str(e))
            delay = int(match.group(1)) if match else RATE_LIMIT_DELAY
            print(f"Aguardando {delay} segundos...")
            time.sleep(delay)
            try:
                return generate_answer(prompt)
            except Exception as e2:
                print("❌ Erro persistente após retry:", e2)
                return None
        else:
            print("❌ Erro:", e)
            return None


def main():

    # Cria pasta de saída caso não exista
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Lista arquivos a processar (tirando já feitos)
    filenames = list(set(os.listdir(INPUT_DIR)) - set(os.listdir(OUTPUT_DIR)))
    print(f"Total de arquivos a processar: {len(filenames)}")

    for idx, filename in enumerate(filenames, start=1):
        print(f"[{idx}/{len(filenames)}] Processando: {filename}")
        try:
            res = process_file(filename)
            if res:
                with open(os.path.join(OUTPUT_DIR, f"{filename[:-4]}.txt"), 'w', encoding='utf-8') as f:
                    f.write(res)
                print("✅ Sucesso")
            else:
                print("⚠️ Sem resultado válido")
        except Exception as e:
            print(f"❌ Exceção geral: {e}")

        # Delay entre chamadas
        time.sleep(REQUEST_DELAY)


if __name__ == "__main__":
    main()
