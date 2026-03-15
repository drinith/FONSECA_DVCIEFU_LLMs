import pandas as pd

# 1. NOMES DOS ARQUIVOS (Devem estar na mesma pasta do script)
file_tp = 'Planilha_Verdadeiros_Positivos.csv'
file_fp = 'Planilha_Falsos_Positivos.csv'
file_gabarito = 'gabarito_vulnerabilidades.csv'

def processar_metricas():
    try:
        # Carregar os CSVs locais
        tp_df = pd.read_csv(file_tp)
        fp_df = pd.read_csv(file_fp)
        gabarito_df = pd.read_csv(file_gabarito)

        vulnerabilidades = [
            'REENTRANCY', 'ACCESS_CONTROL', 'ARITHMETIC', 
            'UNCHECKED_LL_CALLS', 'DENIAL_OF_SERVICE', 
            'BAD_RANDOMNESS', 'FRONT_RUNNING', 
            'TIME_MANIPULATION', 'SHORT_ADDRESSES'
        ]

        results = []

        for vuln in vulnerabilidades:
            # TP e FP: Soma das detecções nas suas planilhas
            tp = tp_df[vuln].sum() if vuln in tp_df.columns else 0
            fp = fp_df[vuln].sum() if vuln in fp_df.columns else 0
            
            # GABARITO: CONTAGEM POR LINHA (Aqui a gente pega todas as falhas do FRONT_RUNNING)
            total_gabarito = len(gabarito_df[gabarito_df['Vulnerabilidade'] == vuln])
            
            # FN: O que o gabarito tem e a ferramenta não achou
            fn = max(0, total_gabarito - tp)
            
            # Cálculos (com trava para não dividir por zero)
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            results.append({
                'Vulnerabilidade': vuln,
                'TP': int(tp),
                'FP': int(fp),
                'FN': int(fn),
                'Gabarito': int(total_gabarito),
                'Precision': round(precision, 4),
                'Recall': round(recall, 4),
                'F1-Score': round(f1, 4)
            })

        # Criar DataFrame
        df_final = pd.DataFrame(results)
        
        # Exibir no terminal/Colab
        print("\n--- RESULTADO FINAL POR INSTÂNCIA ---")
        print(df_final.to_string(index=False))
        
        # Salvar o CSV final
        df_final.to_csv('metricas_finais_locais.csv', index=False)
        print("\n[SUCESSO] Arquivo 'metricas_finais_locais.csv' gerado!")

    except FileNotFoundError as e:
        print(f"\n[ERRO] Arquivo não encontrado: {e.filename}")
        print("Certifique-se de que os nomes dos arquivos estão corretos e na mesma pasta.")
    except Exception as e:
        print(f"\n[ERRO] Ocorreu um problema: {e}")

# Rodar a budega
if __name__ == "__main__":
    processar_metricas()