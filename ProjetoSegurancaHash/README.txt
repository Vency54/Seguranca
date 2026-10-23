PROJETO - SEGURANÇA DA INFORMAÇÃO
Java 8 / Swing / Apache Ant

ESTRUTURA DE PACOTES:
src/
└── seguranca/
    ├── Seguranca.java
    ├── hash/
    │   └── HashPanel.java                 (módulo implementado por você)
    ├── simetrica/
    │   └── SimetricaPanel.java            (reservado para amigo)
    ├── assimetrica/
    │   └── AssimetricaPanel.java          (reservado para amigo)
    └── assinatura/
        └── AssinaturaPanel.java            (reservado para amigo)

ABRIR:
1. Extraia o ZIP.
2. No NetBeans, Arquivo > Abrir Projeto e selecione a pasta ProjetoSegurancaHash.
3. Confirme o JDK 8 e execute com F6.

Se o NetBeans não reconhecer o projeto, crie um projeto Java com Ant e copie a pasta src inteira.

COMO DIVIDIR:
- Interante 1: seguranca.hash.HashPanel
- Integrante 2: seguranca.simetrica.SimetricaPanel
- Interante 3: seguranca.assimetrica.AssimetricaPanel
- Interante 4: seguranca.assinatura.AssinaturaPanel

Cada painel é uma classe independente. Para manter a integração simples, os integrantes devem preservar o nome da classe,
o nome do pacote e o construtor público sem argumentos. Podem adicionar classes auxiliares dentro do respectivo pacote.

HASH:
- SHA-256 de texto e arquivo.
- Comparação com um hash de referência colado pelo usuário.
- Não exige bibliotecas externas.
- SHA-256 é hash, não criptografia reversível.

NOTA:
Os painéis simétrico, assimétrico e assinatura são esqueletos com instruções; ainda precisam ser implementados.


CMD corrigido:
"C:\Program Files\Java\jdk1.8.0_331\bin\keytool.exe" -genkeypair -alias assinatura -keyalg RSA -keysize 2048 -validity 365 -storetype PKCS12 -keystore assinatura.p12 -storepass senha123 -keypass senha123 -dname "CN=Seu Nome, O=ADS"

Link Do Canva:

https://shre.ink/luist
