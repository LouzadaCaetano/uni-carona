# uni-carona
Repositório da prova de Produção, Métricas e Qualidade de software.

## UniCarona — protótipo funcional

Sistema web acadêmico de carona solidária para universitários.

## Executar
1. Abra o terminal nesta pasta.
2. Execute `python server.py`.
3. Abra `http://localhost:8080`.

Não é necessário instalar bibliotecas externas. O SQLite é criado automaticamente.

## Administrador de demonstração
- E-mail: `admin@unicarona.local`
- Senha: `admin123`

## Funcionalidades implementadas
- cadastro e login;
- conta única para passageiro e possível motorista;
- solicitação de carona com origem/destino e GPS opcional;
- acompanhamento da solicitação pelo passageiro;
- solicitação para se tornar motorista com veículo, placa e CNH;
- aprovação ou rejeição manual pelo administrador;
- motorista aprovado vê corridas e pode aceitar ou recusar;
- passageiro vê qual motorista aceitou;
- painel do administrador com usuários, motoristas e caronas.

## Observações
É um protótipo acadêmico local. Não há serviço real de mapas nem consulta oficial de CNH. A aprovação de motorista é manual, conforme o critério de aceite do backlog.
