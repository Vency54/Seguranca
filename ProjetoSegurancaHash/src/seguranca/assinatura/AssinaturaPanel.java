package seguranca.assinatura;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.filechooser.FileNameExtensionFilter;

public class AssinaturaPanel extends JPanel {
    private static final String ALGORITMO = "SHA256withRSA";

    private static final String EXPLICACAO =
        "COMO USAR ESTA ABA (PASSO A PASSO)\n\n"
        + "ANTES DE COMEÇAR (só uma vez): criar o keystore\n"
        + "O keystore é o \"cofre\" que guarda a chave privada e o certificado. Ele é criado pelo terminal, "
        + "fora deste programa:\n"
        + "  a) Crie uma pasta para o teste (por exemplo, teste-assinatura) e coloque nela o arquivo que você "
        + "quer assinar (por exemplo, documento.txt).\n"
        + "  b) Abra o terminal dentro dessa pasta e rode o comando abaixo, em uma linha só "
        + "(o keytool já vem com o JDK):\n\n"
        + "keytool -genkeypair -alias assinatura -keyalg RSA -keysize 2048 -validity 365 -storetype PKCS12 "
        + "-keystore assinatura.p12 -storepass senha123 -keypass senha123 -dname \"CN=Seu Nome, O=ADS\"\n\n"
        + "  c) Pronto: a pasta agora tem o arquivo assinatura.p12, protegido pela senha senha123.\n\n"
        + "USANDO O PROGRAMA\n"
        + "1) Bloco 1: clique em \"Selecionar keystore...\", escolha o assinatura.p12 e digite a senha senha123. "
        + "Deixe o alias como está (assinatura).\n"
        + "2) Bloco 2: clique em \"Selecionar arquivo...\" e escolha o documento.txt. "
        + "Clique em \"Assinar arquivo\": é criado o documento.txt.sig. "
        + "Depois clique em \"Exportar certificado (.cer)\": é criado o assinatura.cer.\n"
        + "3) Bloco 3: os campos da assinatura (.sig) e do certificado (.cer) já aparecem preenchidos. "
        + "Clique em \"Verificar assinatura\". Deve aparecer \"assinatura VÁLIDA\".\n"
        + "4) Teste final: altere uma letra do documento.txt, salve, e clique em \"Verificar assinatura\" "
        + "de novo. Agora deve aparecer \"assinatura INVÁLIDA\". "
        + "Isso prova que a assinatura detecta qualquer alteração no arquivo.\n\n"
        + "ONDE FICAM OS ARQUIVOS\n"
        + "O .sig é salvo ao lado do arquivo assinado e o .cer ao lado do keystore. "
        + "Se o keystore e o documento estiverem na mesma pasta, tudo fica junto. "
        + "O caminho completo de cada arquivo aparece nos campos da tela.\n\n"
        + "COMO FUNCIONA\n"
        + "A assinatura usa SHA256withRSA: o arquivo passa por SHA-256 e o hash é cifrado com a chave privada. "
        + "Quem verifica usa o certificado (que contém só a chave pública), "
        + "sem precisar da chave privada.";

    private final JTextField keystoreCaminho = new JTextField();
    private final JPasswordField senhaKeystore = new JPasswordField();
    private final JTextField aliasCampo = new JTextField("assinatura");
    private final JTextField arquivoCaminho = new JTextField();
    private final JTextField assinaturaBase64 = new JTextField();
    private final JTextField assinaturaCaminho = new JTextField();
    private final JTextField certificadoCaminho = new JTextField();
    private final JLabel resultado = new JLabel("Selecione o keystore e o arquivo a assinar.", SwingConstants.LEFT);
    private File keystoreArquivo;
    private File arquivoSelecionado;
    private File arquivoAssinatura;
    private File arquivoCertificado;

    public AssinaturaPanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel conteudo = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(5, 5, 5, 5);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;
        c.gridx = 0;
        c.gridy = 0;

        JTextArea explicacao = new JTextArea(EXPLICACAO, 18, 50);
        explicacao.setEditable(false);
        explicacao.setLineWrap(true);
        explicacao.setWrapStyleWord(true);
        conteudo.add(new JScrollPane(explicacao), c);

        c.gridy++;
        conteudo.add(new JLabel("1. Carregar o keystore (chave privada + certificado)"), c);

        c.gridy++;
        JPanel keystoreBotoes = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton selecionarKeystore = new JButton("Selecionar keystore...");
        selecionarKeystore.addActionListener(e -> selecionarKeystore());
        keystoreBotoes.add(selecionarKeystore);
        conteudo.add(keystoreBotoes, c);

        c.gridy++;
        keystoreCaminho.setEditable(false);
        conteudo.add(keystoreCaminho, c);

        c.gridy++;
        conteudo.add(new JLabel("Senha do keystore:"), c);

        c.gridy++;
        conteudo.add(senhaKeystore, c);

        c.gridy++;
        conteudo.add(new JLabel("Alias da chave (em branco = primeira chave do keystore):"), c);

        c.gridy++;
        conteudo.add(aliasCampo, c);

        c.gridy++;
        conteudo.add(new JLabel("2. Assinar um arquivo"), c);

        c.gridy++;
        JPanel assinarBotoes = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton selecionarArquivo = new JButton("Selecionar arquivo...");
        selecionarArquivo.addActionListener(e -> selecionarArquivo());
        JButton assinar = new JButton("Assinar arquivo");
        assinar.addActionListener(e -> assinarArquivo());
        JButton exportar = new JButton("Exportar certificado (.cer)");
        exportar.addActionListener(e -> exportarCertificado());
        assinarBotoes.add(selecionarArquivo);
        assinarBotoes.add(assinar);
        assinarBotoes.add(exportar);
        conteudo.add(assinarBotoes, c);

        c.gridy++;
        arquivoCaminho.setEditable(false);
        conteudo.add(arquivoCaminho, c);

        c.gridy++;
        conteudo.add(new JLabel("Assinatura gerada (Base64; também salva em um arquivo .sig):"), c);

        c.gridy++;
        assinaturaBase64.setEditable(false);
        conteudo.add(assinaturaBase64, c);

        c.gridy++;
        conteudo.add(new JLabel("3. Verificar a assinatura (usa o arquivo selecionado no passo 2)"), c);

        c.gridy++;
        JPanel verificarBotoes = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton selecionarAssinatura = new JButton("Selecionar assinatura (.sig)...");
        selecionarAssinatura.addActionListener(e -> selecionarAssinatura());
        JButton selecionarCertificado = new JButton("Selecionar certificado (.cer)...");
        selecionarCertificado.addActionListener(e -> selecionarCertificado());
        JButton verificar = new JButton("Verificar assinatura");
        verificar.addActionListener(e -> verificarAssinatura());
        JButton limpar = new JButton("Limpar");
        limpar.addActionListener(e -> limpar());
        verificarBotoes.add(selecionarAssinatura);
        verificarBotoes.add(selecionarCertificado);
        verificarBotoes.add(verificar);
        verificarBotoes.add(limpar);
        conteudo.add(verificarBotoes, c);

        c.gridy++;
        conteudo.add(new JLabel("Assinatura (.sig):"), c);

        c.gridy++;
        assinaturaCaminho.setEditable(false);
        conteudo.add(assinaturaCaminho, c);

        c.gridy++;
        conteudo.add(new JLabel("Certificado (.cer):"), c);

        c.gridy++;
        certificadoCaminho.setEditable(false);
        conteudo.add(certificadoCaminho, c);

        c.gridy++;
        resultado.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        conteudo.add(resultado, c);
        add(new JScrollPane(conteudo), BorderLayout.CENTER);
    }

    private void selecionarKeystore() {
        File arquivo = escolherArquivo("Selecione o keystore (.p12 ou .jks)",
            new FileNameExtensionFilter("Keystore (*.p12, *.pfx, *.jks)", "p12", "pfx", "jks"));
        if (arquivo != null) {
            keystoreArquivo = arquivo;
            keystoreCaminho.setText(arquivo.getAbsolutePath());
            resultado.setText("Keystore selecionado: " + arquivo.getName());
        }
    }

    private void selecionarArquivo() {
        File arquivo = escolherArquivo("Selecione o arquivo para assinar ou verificar", null);
        if (arquivo != null) {
            arquivoSelecionado = arquivo;
            arquivoCaminho.setText(arquivo.getAbsolutePath());
            resultado.setText("Arquivo selecionado: " + arquivo.getName());
        }
    }

    private void selecionarAssinatura() {
        File arquivo = escolherArquivo("Selecione o arquivo de assinatura (.sig)",
            new FileNameExtensionFilter("Assinatura (*.sig)", "sig"));
        if (arquivo != null) {
            arquivoAssinatura = arquivo;
            assinaturaCaminho.setText(arquivo.getAbsolutePath());
            resultado.setText("Assinatura selecionada: " + arquivo.getName());
        }
    }

    private void selecionarCertificado() {
        File arquivo = escolherArquivo("Selecione o certificado (.cer)",
            new FileNameExtensionFilter("Certificado (*.cer, *.crt, *.pem)", "cer", "crt", "pem"));
        if (arquivo != null) {
            arquivoCertificado = arquivo;
            certificadoCaminho.setText(arquivo.getAbsolutePath());
            resultado.setText("Certificado selecionado: " + arquivo.getName());
        }
    }

    private File escolherArquivo(String titulo, FileNameExtensionFilter filtro) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(titulo);
        if (filtro != null) {
            chooser.setFileFilter(filtro);
        }
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    private void assinarArquivo() {
        if (!keystoreInformado()) {
            return;
        }
        if (arquivoSelecionado == null) {
            JOptionPane.showMessageDialog(this, "Selecione o arquivo a ser assinado.",
                "Nenhum arquivo", JOptionPane.WARNING_MESSAGE);
            return;
        }
        char[] senha = senhaKeystore.getPassword();
        try {
            KeyStore keystore = carregarKeystore(keystoreArquivo, senha);
            String alias = escolherAlias(keystore);
            Key chave = alias == null ? null : keystore.getKey(alias, senha);
            if (!(chave instanceof PrivateKey)) {
                mostrarErro("Não foi encontrada uma chave privada no keystore para o alias informado.");
                return;
            }

            Signature assinatura = Signature.getInstance(ALGORITMO);
            assinatura.initSign((PrivateKey) chave);
            alimentar(assinatura, arquivoSelecionado);
            byte[] bytesAssinatura = assinatura.sign();

            File destino = new File(arquivoSelecionado.getParentFile(), arquivoSelecionado.getName() + ".sig");
            Files.write(destino.toPath(), bytesAssinatura);
            arquivoAssinatura = destino;
            assinaturaCaminho.setText(destino.getAbsolutePath());
            assinaturaBase64.setText(Base64.getEncoder().encodeToString(bytesAssinatura));
            resultado.setText("Arquivo assinado. Assinatura salva em: " + destino.getName());
        } catch (GeneralSecurityException ex) {
            mostrarErro("Não foi possível assinar o arquivo: " + ex.getMessage());
        } catch (IOException ex) {
            mostrarErro("Erro ao abrir ou gravar arquivo: " + ex.getMessage());
        } finally {
            Arrays.fill(senha, '\0');
        }
    }

    private void exportarCertificado() {
        if (!keystoreInformado()) {
            return;
        }
        char[] senha = senhaKeystore.getPassword();
        try {
            KeyStore keystore = carregarKeystore(keystoreArquivo, senha);
            String alias = escolherAlias(keystore);
            Certificate certificado = alias == null ? null : keystore.getCertificate(alias);
            if (certificado == null) {
                mostrarErro("Não foi encontrado um certificado no keystore para o alias informado.");
                return;
            }

            File destino = new File(keystoreArquivo.getParentFile(), alias + ".cer");
            Files.write(destino.toPath(), certificado.getEncoded());
            arquivoCertificado = destino;
            certificadoCaminho.setText(destino.getAbsolutePath());
            resultado.setText("Certificado exportado: " + destino.getName()
                + " (já selecionado para a verificação).");
        } catch (GeneralSecurityException ex) {
            mostrarErro("Não foi possível exportar o certificado: " + ex.getMessage());
        } catch (IOException ex) {
            mostrarErro("Erro ao abrir ou gravar arquivo: " + ex.getMessage());
        } finally {
            Arrays.fill(senha, '\0');
        }
    }

    private void verificarAssinatura() {
        if (arquivoSelecionado == null) {
            JOptionPane.showMessageDialog(this, "Selecione o arquivo original (passo 2).",
                "Nenhum arquivo", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (arquivoAssinatura == null) {
            JOptionPane.showMessageDialog(this, "Selecione o arquivo de assinatura (.sig).",
                "Nenhuma assinatura", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (arquivoCertificado == null) {
            JOptionPane.showMessageDialog(this, "Selecione o certificado (.cer) ou exporte-o do keystore.",
                "Nenhum certificado", JOptionPane.WARNING_MESSAGE);
            return;
        }
        try (FileInputStream entradaCertificado = new FileInputStream(arquivoCertificado)) {
            X509Certificate certificado = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(entradaCertificado);
            certificado.checkValidity();
            byte[] bytesAssinatura = Files.readAllBytes(arquivoAssinatura.toPath());

            Signature assinatura = Signature.getInstance(ALGORITMO);
            assinatura.initVerify(certificado.getPublicKey());
            alimentar(assinatura, arquivoSelecionado);

            boolean valida;
            try {
                valida = assinatura.verify(bytesAssinatura);
            } catch (SignatureException ex) {
                valida = false; // assinatura com formato inválido (ex.: não é um arquivo .sig)
            }

            if (valida) {
                resultado.setText("RESULTADO: assinatura VÁLIDA. O arquivo não foi alterado e confere com o certificado.");
                JOptionPane.showMessageDialog(this, "A assinatura é válida.",
                    "Assinatura verificada", JOptionPane.INFORMATION_MESSAGE);
            } else {
                resultado.setText("RESULTADO: assinatura INVÁLIDA. O arquivo foi alterado ou a assinatura/certificado não correspondem.");
                JOptionPane.showMessageDialog(this, "A assinatura é inválida.",
                    "Assinatura inválida", JOptionPane.WARNING_MESSAGE);
            }
        } catch (CertificateExpiredException | CertificateNotYetValidException ex) {
            mostrarErro("O certificado não está dentro do prazo de validade: " + ex.getMessage());
        } catch (GeneralSecurityException ex) {
            mostrarErro("Não foi possível verificar a assinatura: " + ex.getMessage());
        } catch (IOException ex) {
            mostrarErro("Erro ao ler arquivo: " + ex.getMessage());
        }
    }

    private void limpar() {
        keystoreArquivo = null;
        arquivoSelecionado = null;
        arquivoAssinatura = null;
        arquivoCertificado = null;
        keystoreCaminho.setText("");
        senhaKeystore.setText("");
        aliasCampo.setText("assinatura");
        arquivoCaminho.setText("");
        assinaturaBase64.setText("");
        assinaturaCaminho.setText("");
        certificadoCaminho.setText("");
        resultado.setText("Selecione o keystore e o arquivo a assinar.");
    }

    private boolean keystoreInformado() {
        if (keystoreArquivo == null) {
            JOptionPane.showMessageDialog(this, "Selecione o keystore primeiro.",
                "Nenhum keystore", JOptionPane.WARNING_MESSAGE);
            return false;
        }
        if (senhaKeystore.getPassword().length == 0) {
            JOptionPane.showMessageDialog(this, "Digite a senha do keystore.",
                "Senha vazia", JOptionPane.WARNING_MESSAGE);
            return false;
        }
        return true;
    }

    private KeyStore carregarKeystore(File arquivo, char[] senha) throws GeneralSecurityException, IOException {
        IOException ultimoErro = null;
        for (String tipo : new String[] {"PKCS12", "JKS"}) {
            try (FileInputStream entrada = new FileInputStream(arquivo)) {
                KeyStore keystore = KeyStore.getInstance(tipo);
                keystore.load(entrada, senha);
                return keystore;
            } catch (IOException ex) {
                ultimoErro = ex;
            }
        }
        throw new IOException("Não foi possível abrir o keystore. Verifique o arquivo e a senha.", ultimoErro);
    }

    private String escolherAlias(KeyStore keystore) throws KeyStoreException {
        String informado = aliasCampo.getText().trim();
        if (!informado.isEmpty()) {
            return informado;
        }
        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keystore.isKeyEntry(alias)) {
                return alias;
            }
        }
        return null;
    }

    private void alimentar(Signature assinatura, File arquivo) throws IOException, SignatureException {
        try (FileInputStream entrada = new FileInputStream(arquivo)) {
            byte[] buffer = new byte[8192];
            int quantidade;
            while ((quantidade = entrada.read(buffer)) != -1) {
                assinatura.update(buffer, 0, quantidade);
            }
        }
    }

    private void mostrarErro(String mensagem) {
        JOptionPane.showMessageDialog(this, mensagem, "Erro", JOptionPane.ERROR_MESSAGE);
    }
}