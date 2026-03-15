# Análise de Vulnerabilidades em Smart Contracts: Replicação Experimental com Gemini 2.0 Flash

Este repositório contém os artefatos de software desenvolvidos para o estudo de detecção de vulnerabilidades em *smart contracts* (Solidity) utilizando o modelo **Gemini 2.0 Flash**.

## 🎯 Objetivo
O projeto visa replicar e estender a metodologia proposta por **Chen et al.** no estudo fundamental *"When ChatGPT meets smart contract vulnerability detection: How far are we?"*. O objetivo é avaliar se o comportamento e a eficácia observados no ChatGPT se mantêm ao utilizar o modelo Gemini 2.0 Flash, seguindo o mesmo rigor metodológico na identificação de falhas da taxonomia **DASP Top 10**.

## 🛠 Arquitetura do Experimento
A estrutura do projeto espelha o *pipeline* de pesquisa original:

### 1. `experiment_gemini.py`
Este script implementa o módulo de **inferência automatizada**. 
* **Contexto**: Seguindo os critérios de *prompting* estabelecidos por Chen et al., este script submete os contratos do *dataset* `smartbugs-curated` ao Gemini 2.0 Flash.
* **Funcionalidade**: Gerenciamento de chamadas de API, controle de concorrência e coleta de respostas, assegurando que o ambiente de teste seja controlado e reprodutível.

### 2. `avaliador_binario.py`
Este script atua como o módulo de **validação empírica**.
* **Contexto**: Dado que LLMs geram explicações textuais variadas, este script aplica a lógica de normalização necessária para converter essas saídas em dados estruturados (matriz binária 0/1).
* **Funcionalidade**: Comparação das detecções do modelo com o *Ground Truth* do *dataset*, permitindo o cálculo estatístico de **Precision, Recall e F1-Score**. Isso permite uma comparação direta "lado a lado" com os resultados apresentados no trabalho base de Chen et al.

## 🚀 Como Executar
1. **Configuração**: Certifique-se de que a API Key do Gemini esteja configurada no ambiente.
2. **Coleta**: Execute o experimento para gerar o log de respostas:
   ```bash
   python experiment_gemini.py

---

*Desenvolvido por: Felipe Mello Fonseca*
*Orientação: Diogo Silveira Mendonça (CEFET-RJ)*