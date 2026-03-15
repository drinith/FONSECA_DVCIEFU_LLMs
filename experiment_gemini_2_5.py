import os
import time
from dotenv import load_dotenv
import google.generativeai as genai
from func_timeout import func_set_timeout
import func_timeout


# =================================================================
# 1. Configuração de Ambiente e Rotação de Chaves
# =================================================================
load_dotenv()

def carregar_chaves():
    """Lê as chaves do .env (API_KEYS=k1,k2 ou GOOGLE_API_KEY=k1)."""
    keys_str = os.getenv("API_KEYS", "")
    lista_chaves = [k.strip() for k in keys_str.split(",") if k.strip()]
    if not lista_chaves:
        single_key = os.getenv("GOOGLE_API_KEY")
        if single_key:
            return [single_key]
        raise EnvironmentError("❌ Nenhuma API_KEY encontrada no .env.")
    return lista_chaves

API_KEYS = carregar_chaves()
current_key_index = 0
MODEL_NAME = 'gemini-2.5-flash'
TIMEOUT_SECONDS = 100
REQUEST_DELAY = 4  # Delay entre chamadas bem-sucedidas

def configurar_gemini():
    """Configura o modelo Gemini com a chave de API atual."""
    global current_key_index, model
    chave_atual = API_KEYS[current_key_index]
    genai.configure(api_key=chave_atual)
    model = genai.GenerativeModel(MODEL_NAME)

configurar_gemini()

# =================================================================
# 2. Configurações de Diretório
# =================================================================

# Lista de arquivos já processados
xx = os.listdir("./results_gemini_teste/")
xxx = [i[:-4] + '.sol' for i in xx]
filenames = list(set(os.listdir("./smartbugs-curated/dataset/processed")) - set(xxx))
position_file = 0
error_cnt = 0

# =================================================================
# 3. Funções de Processamento
# =================================================================

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

@func_set_timeout(TIMEOUT_SECONDS)
def call_gemini_api(prompt: str) -> str:
    """Chamada direta ao modelo."""
    response = model.generate_content(prompt)
    return response.text.strip()

def generate_answer(prompt: str) -> str:
    """Gera resposta com lógica de rotação de chaves em caso de erro de cota ou chave inválida/expirada."""
    global current_key_index

    # Erros que indicam que a chave atual deve ser trocada
    ROTATE_TRIGGERS = [
        "429", "quota", "limit", "exhausted",   # cota esgotada
        "api_key_invalid", "key expired", "invalid api key",  # chave inválida/expirada
    ]

    for tentativa in range(len(API_KEYS)):
        try:
            res = call_gemini_api(prompt)
            return res
        except func_timeout.exceptions.FunctionTimedOut:
            print("⚠️ Timeout na chamada")
            return None
        except Exception as e:
            msg = str(e).lower()
            if any(x in msg for x in ROTATE_TRIGGERS):
                proximo_index = (current_key_index + 1) % len(API_KEYS)
                if proximo_index == current_key_index:
                    # Só há uma chave — não adianta rotacionar
                    print(f"❌ Chave inválida/expirada e não há outras chaves disponíveis.")
                    return None
                print(f"🔄 [CHAVE INVÁLIDA] Chave {current_key_index + 1} falhou ({str(e)[:60]}...). "
                      f"Alternando para chave {proximo_index + 1}...")
                time.sleep(5)  # Pausa curta — chave inválida não precisa de 20s
                current_key_index = proximo_index
                configurar_gemini()
                continue
            else:
                print(f"❌ Erro inesperado na API: {e}")
                return None

    print("❌ Todas as chaves falharam.")
    return None

# =================================================================
# 4. Loop principal
# =================================================================

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

    except Exception as e:
        print("error:", e)
        position_file += 1
        continue

    if res:
        print("success, outputting...")
        with open('./results_gemini_teste/' + filename[:-4] + '.txt', 'w') as f:
            f.write(res)
        time.sleep(REQUEST_DELAY)  # Delay para respeitar o RPM da conta
    else:
        print(f"⚠️ Falha ao obter resposta para {filename}")

    position_file += 1