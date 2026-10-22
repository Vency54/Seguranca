package seguranca.assimetrica;


import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

public class AssimetricaPanel extends JPanel {

    // Componentes para Exibição das Chaves
    private final JTextArea chavePublicaArea = new JTextArea(3, 50);
    private final JTextArea chavePrivadaArea = new JTextArea(3, 50);

    // Componentes para Entrada/Saída de Texto
    private final JTextArea mensagemOriginalArea = new JTextArea(3, 50);
    private final JTextArea mensagemCriptografadaArea = new JTextArea(3, 50);
    private final JTextField mensagemDescriptografadaField = new JTextField();

    private final JLabel resultado = new JLabel("Gere o par de chaves RSA para iniciar.", SwingConstants.LEFT);

    // Atributos de Criptografia
    private KeyPair keyPair;

    public AssimetricaPanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel conteudo = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(5, 5, 5, 5);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 2;

        // --- SEÇÃO 1: GERAR CHAVES ---
        conteudo.add(new JLabel("1. Gerar Par de Chaves RSA (2048 bits)"), c);

        c.gridy++;
        c.gridwidth = 1;
        JButton btnGerarChaves = new JButton("Gerar Par de Chaves");
        btnGerarChaves.addActionListener(e -> gerarChavesRSA());
        conteudo.add(btnGerarChaves, c);

        JButton btnLimpar = new JButton("Limpar Tudo");
        btnLimpar.addActionListener(e -> limparCampos());
        c.gridx = 1;
        conteudo.add(btnLimpar, c);

        // Exibição da Chave Pública
        c.gridx = 0;
        c.gridy++;
        c.gridwidth = 2;
        conteudo.add(new JLabel("Chave Pública (para Criptografar):"), c);

        c.gridy++;
        chavePublicaArea.setEditable(false);
        chavePublicaArea.setLineWrap(true);
        conteudo.add(new JScrollPane(chavePublicaArea), c);

        // Exibição da Chave Privada
        c.gridy++;
        conteudo.add(new JLabel("Chave Privada (para Descriptografar):"), c);

        c.gridy++;
        chavePrivadaArea.setEditable(false);
        chavePrivadaArea.setLineWrap(true);
        conteudo.add(new JScrollPane(chavePrivadaArea), c);

        // --- SEÇÃO 2: CRIPTOGRAFAR ---
        c.gridy++;
        conteudo.add(new JLabel("2. Mensagem Original (Texto Puro)"), c);

        c.gridy++;
        mensagemOriginalArea.setLineWrap(true);
        mensagemOriginalArea.setWrapStyleWord(true);
        conteudo.add(new JScrollPane(mensagemOriginalArea), c);

        c.gridy++;
        JButton btnCriptografar = new JButton("Criptografar com Chave Pública");
        btnCriptografar.addActionListener(e -> criptografarMensagem());
        conteudo.add(btnCriptografar, c);

        c.gridy++;
        conteudo.add(new JLabel("Mensagem Criptografada (Base64 / Texto Cifrado):"), c);

        c.gridy++;
        mensagemCriptografadaArea.setEditable(false);
        mensagemCriptografadaArea.setLineWrap(true);
        conteudo.add(new JScrollPane(mensagemCriptografadaArea), c);

        // --- SEÇÃO 3: DESCRIPTOGRAFAR ---
        c.gridy++;
        conteudo.add(new JLabel("3. Processo de Descriptografia"), c);

        c.gridy++;
        JButton btnDescriptografar = new JButton("Descriptografar com Chave Privada");
        btnDescriptografar.addActionListener(e -> descriptografarMensagem());
        conteudo.add(btnDescriptografar, c);

        c.gridy++;
        conteudo.add(new JLabel("Mensagem Recuperada:"), c);

        c.gridy++;
        mensagemDescriptografadaField.setEditable(false);
        conteudo.add(mensagemDescriptografadaField, c);

        // --- STATUS / RESULTADO ---
        c.gridy++;
        resultado.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        conteudo.add(resultado, c);

        add(new JScrollPane(conteudo), BorderLayout.CENTER);
    }

    // Regra de Negócio: Geração do Par de Chaves RSA
    private void gerarChavesRSA() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            this.keyPair = keyGen.generateKeyPair();

            chavePublicaArea.setText(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            chavePrivadaArea.setText(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));

            resultado.setText("Par de chaves gerado com sucesso! Agora digite a mensagem original.");
        } catch (NoSuchAlgorithmException ex) {
            mostrarErro("Erro ao gerar chaves RSA: " + ex.getMessage());
        }
    }

    // Regra de Negócio: Criptografia com Chave Pública
    private void criptografarMensagem() {
        if (keyPair == null) {
            JOptionPane.showMessageDialog(this, "Gere o par de chaves antes de criptografar.",
                    "Chaves não geradas", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String texto = mensagemOriginalArea.getText();
        if (texto.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Digite uma mensagem para criptografar.",
                    "Campo vazio", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

            byte[] bytesCriptografados = cipher.doFinal(texto.getBytes(StandardCharsets.UTF_8));
            String textoCifradoBase64 = Base64.getEncoder().encodeToString(bytesCriptografados);

            mensagemCriptografadaArea.setText(textoCifradoBase64);
            resultado.setText("Mensagem criptografada com a Chave Pública com sucesso!");
        } catch (Exception ex) {
            mostrarErro("Erro ao criptografar mensagem: " + ex.getMessage());
        }
    }

    // Regra de Negócio: Descriptografia com Chave Privada
    private void descriptografarMensagem() {
        if (keyPair == null) {
            JOptionPane.showMessageDialog(this, "Gere o par de chaves antes de descriptografar.",
                    "Chaves não geradas", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String textoCifradoBase64 = mensagemCriptografadaArea.getText();
        if (textoCifradoBase64.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Criptografe uma mensagem primeiro para obter o texto cifrado.",
                    "Texto cifrado vazio", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

            byte[] bytesCifrados = Base64.getDecoder().decode(textoCifradoBase64);
            byte[] bytesDecifrados = cipher.doFinal(bytesCifrados);

            String textoRecuperado = new String(bytesDecifrados, StandardCharsets.UTF_8);
            mensagemDescriptografadaField.setText(textoRecuperado);

            resultado.setText("Mensagem descriptografada com sucesso usando a Chave Privada.");
        } catch (Exception ex) {
            mostrarErro("Erro ao descriptografar mensagem: " + ex.getMessage());
        }
    }

    private void limparCampos() {
        keyPair = null;
        chavePublicaArea.setText("");
        chavePrivadaArea.setText("");
        mensagemOriginalArea.setText("");
        mensagemCriptografadaArea.setText("");
        mensagemDescriptografadaField.setText("");
        resultado.setText("Gere o par de chaves RSA para iniciar.");
    }

    private void mostrarErro(String mensagem) {
        JOptionPane.showMessageDialog(this, mensagem, "Erro", JOptionPane.ERROR_MESSAGE);
    }
}