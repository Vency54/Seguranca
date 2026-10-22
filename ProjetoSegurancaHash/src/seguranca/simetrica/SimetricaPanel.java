package seguranca.simetrica;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

/**
 * Demonstração didática de criptografia simétrica usando AES-GCM.
 * A mesma chave secreta é usada para criptografar e descriptografar.
 */
public class SimetricaPanel extends JPanel {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE_BITS = 128;
    private static final int IV_SIZE_BYTES = 12;
    private static final int TAG_SIZE_BITS = 128;

    private final SecureRandom secureRandom = new SecureRandom();
    private final JTextField keyField = new JTextField();
    private final JTextArea plainTextArea = new JTextArea(4, 50);
    private final JTextArea cipherTextArea = new JTextArea(5, 50);
    private final JTextArea decryptedTextArea = new JTextArea(4, 50);
    private final JLabel statusLabel = new JLabel(" ");
    private SecretKey secretKey;

    public SimetricaPanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(18, 22, 18, 22));

        JLabel title = new JLabel("Demonstração de criptografia simétrica (AES-GCM)", SwingConstants.CENTER);
        add(title, BorderLayout.NORTH);

        plainTextArea.setLineWrap(true);
        plainTextArea.setWrapStyleWord(true);
        cipherTextArea.setLineWrap(true);
        cipherTextArea.setWrapStyleWord(true);
        cipherTextArea.setEditable(false);
        decryptedTextArea.setLineWrap(true);
        decryptedTextArea.setWrapStyleWord(true);
        decryptedTextArea.setEditable(false);
        keyField.setEditable(false);

        JPanel fields = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 0;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.insets = new Insets(5, 4, 5, 8);
        fields.add(new JLabel("Chave secreta (Base64):"), c);

        c.gridx = 1;
        c.weightx = 1;
        c.insets = new Insets(5, 0, 5, 4);
        fields.add(keyField, c);

        addField(fields, c, 1, "Texto original:", new JScrollPane(plainTextArea));
        addField(fields, c, 2, "Texto cifrado (Base64):", new JScrollPane(cipherTextArea));
        addField(fields, c, 3, "Texto após descriptografar:", new JScrollPane(decryptedTextArea));
        addField(fields, c, 4, "Processo:", new JLabel(
            "AES-GCM protege a mensagem; a mesma chave secreta é usada nas duas operações. "
            + "O IV é aleatório e segue junto com o texto cifrado; ele não é a chave."
        ));

        add(new JScrollPane(fields), BorderLayout.CENTER);

        JButton newKeyButton = new JButton("Gerar nova chave");
        JButton encryptButton = new JButton("Criptografar");
        JButton decryptButton = new JButton("Descriptografar");
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(newKeyButton);
        buttons.add(encryptButton);
        buttons.add(decryptButton);

        JPanel bottom = new JPanel(new BorderLayout(5, 5));
        bottom.add(buttons, BorderLayout.NORTH);
        bottom.add(statusLabel, BorderLayout.SOUTH);
        add(bottom, BorderLayout.SOUTH);

        newKeyButton.addActionListener(e -> generateNewKey());
        encryptButton.addActionListener(e -> encryptMessage());
        decryptButton.addActionListener(e -> decryptMessage());

        generateNewKey();
    }

    private void addField(JPanel panel, GridBagConstraints c, int row, String label, java.awt.Component component) {
        c.gridx = 0;
        c.gridy = row;
        c.weightx = 0;
        c.weighty = row == 4 ? 0 : 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.insets = new Insets(5, 4, 5, 8);
        panel.add(new JLabel(label), c);

        c.gridx = 1;
        c.weightx = 1;
        c.weighty = row == 4 ? 0 : 1;
        c.fill = row == 4 ? GridBagConstraints.HORIZONTAL : GridBagConstraints.BOTH;
        c.insets = new Insets(5, 0, 5, 4);
        panel.add(component, c);
    }

    private void generateNewKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_SIZE_BITS, secureRandom);
            secretKey = keyGenerator.generateKey();
            keyField.setText(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
            decryptedTextArea.setText("");
            statusLabel.setText("Nova chave AES gerada. Use esta mesma chave para criptografar e descriptografar.");
        } catch (GeneralSecurityException ex) {
            secretKey = null;
            keyField.setText("");
            statusLabel.setText("Não foi possível gerar a chave: " + ex.getMessage());
        }
    }

    private void encryptMessage() {
        if (secretKey == null) {
            statusLabel.setText("Gere uma chave antes de criptografar.");
            return;
        }
        try {
            byte[] iv = new byte[IV_SIZE_BYTES];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_SIZE_BITS, iv));
            byte[] encrypted = cipher.doFinal(plainTextArea.getText().getBytes(StandardCharsets.UTF_8));

            // Formato demonstrativo: IV (12 bytes) seguido dos dados cifrados e da tag de autenticação.
            byte[] result = ByteBuffer.allocate(iv.length + encrypted.length)
                .put(iv)
                .put(encrypted)
                .array();
            cipherTextArea.setText(Base64.getEncoder().encodeToString(result));
            decryptedTextArea.setText("");
            statusLabel.setText("Mensagem criptografada. O IV foi incluído no resultado em Base64.");
        } catch (GeneralSecurityException ex) {
            statusLabel.setText("Erro ao criptografar: " + ex.getMessage());
        }
    }

    private void decryptMessage() {
        if (secretKey == null) {
            statusLabel.setText("Não há uma chave disponível. Gere uma chave e use a mesma que cifrou a mensagem.");
            return;
        }
        try {
            byte[] combined = Base64.getDecoder().decode(cipherTextArea.getText().trim());
            // IV de 12 bytes e tag GCM de 16 bytes são necessários, mesmo para texto vazio.
            if (combined.length < IV_SIZE_BYTES + TAG_SIZE_BITS / 8) {
                statusLabel.setText("Texto cifrado inválido ou incompleto.");
                return;
            }

            ByteBuffer buffer = ByteBuffer.wrap(combined);
            byte[] iv = new byte[IV_SIZE_BYTES];
            buffer.get(iv);
            byte[] encrypted = new byte[buffer.remaining()];
            buffer.get(encrypted);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_SIZE_BITS, iv));
            byte[] plainText = cipher.doFinal(encrypted);
            decryptedTextArea.setText(new String(plainText, StandardCharsets.UTF_8));
            statusLabel.setText("Descriptografia concluída com a mesma chave secreta.");
        } catch (IllegalArgumentException ex) {
            statusLabel.setText("O texto cifrado não está em um formato Base64 válido.");
        } catch (GeneralSecurityException ex) {
            decryptedTextArea.setText("");
            statusLabel.setText("Falha na descriptografia. Verifique se a chave e o texto cifrado correspondem.");
        }
    }
}
