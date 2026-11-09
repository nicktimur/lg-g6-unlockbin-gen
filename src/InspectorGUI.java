import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.Timer;

public final class InspectorGUI extends JFrame {
    private final JTextField file = new JTextField(34);
    private final JPasswordField imei = new JPasswordField(18);
    private final JTextField deviceId = new JTextField(55);
    private final JTextArea log = new JTextArea(13, 75);
    private final JLabel status = new JLabel("Ready");
    private final JLabel elapsed = new JLabel("Elapsed: 0.0 s");
    private final JProgressBar progress = new JProgressBar(0, 4);
    private final JButton start = new JButton("Verify file");
    private final JButton cancel = new JButton("Cancel");
    private SwingWorker<Boolean, String> worker;
    private Timer clock;
    private long startNanos;

    public InspectorGUI() {
        super("LG G6 unlock.bin — Offline Validator");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout(8, 8));
        JPanel fields = new JPanel(new GridLayout(3, 1, 5, 5));
        JPanel fileRow = new JPanel(new BorderLayout(5, 0));
        fileRow.add(new JLabel("unlock.bin file:"), BorderLayout.WEST);
        fileRow.add(file, BorderLayout.CENTER);
        JButton browse = new JButton("Browse");
        browse.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                file.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });
        fileRow.add(browse, BorderLayout.EAST);
        fields.add(fileRow);
        JPanel imeiRow = new JPanel(new BorderLayout(5, 0));
        imeiRow.add(new JLabel("IMEI (local only):"), BorderLayout.WEST);
        imeiRow.add(imei, BorderLayout.CENTER);
        fields.add(imeiRow);
        JPanel idRow = new JPanel(new BorderLayout(5, 0));
        idRow.add(new JLabel("Device ID:"), BorderLayout.WEST);
        idRow.add(deviceId, BorderLayout.CENTER);
        fields.add(idRow);
        fields.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 10));
        add(fields, BorderLayout.NORTH);

        log.setEditable(false);
        log.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        add(new JScrollPane(log), BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout(5, 5));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        start.addActionListener(this::runVerification);
        cancel.setEnabled(false);
        cancel.addActionListener(e -> {
            if (worker != null) worker.cancel(true);
        });
        actions.add(start);
        actions.add(cancel);
        actions.add(elapsed);
        bottom.add(actions, BorderLayout.NORTH);
        progress.setStringPainted(true);
        progress.setString("Waiting");
        bottom.add(progress, BorderLayout.CENTER);
        bottom.add(status, BorderLayout.SOUTH);
        bottom.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));
        add(bottom, BorderLayout.SOUTH);
        pack();
        setMinimumSize(new Dimension(740, 440));
        setLocationRelativeTo(null);
        addLog("Ready. This program verifies an existing file; it cannot generate an RSA signature.");
    }

    private void addLog(String message) {
        String time = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        log.append("[" + time + "] " + message + "\n");
        log.setCaretPosition(log.getDocument().getLength());
    }

    private void runVerification(ActionEvent event) {
        if (worker != null && !worker.isDone()) return;
        String path = file.getText().trim();
        char[] secret = imei.getPassword();
        String localImei = new String(secret);
        java.util.Arrays.fill(secret, '\0');
        String localId = deviceId.getText().trim();
        if (!localImei.matches("[0-9]{15}") || !localId.matches("(?i)[0-9a-f]{64}")) {
            JOptionPane.showMessageDialog(this, "Enter a 15-digit IMEI and a 64-character hex Device ID.",
                    "Invalid input", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (!Files.isRegularFile(Path.of(path))) {
            JOptionPane.showMessageDialog(this, "Select an existing unlock.bin file.",
                    "File not found", JOptionPane.ERROR_MESSAGE);
            return;
        }
        log.setText("");
        progress.setValue(0);
        progress.setString("Starting");
        status.setText("Working");
        start.setEnabled(false);
        cancel.setEnabled(true);
        startNanos = System.nanoTime();
        clock = new Timer(100, e -> elapsed.setText(String.format("Elapsed: %.1f s",
                (System.nanoTime() - startNanos) / 1_000_000_000.0)));
        clock.start();
        worker = new SwingWorker<Boolean, String>() {
            @Override protected Boolean doInBackground() throws Exception {
                publish("Step 1/4: Reading file");
                byte[] bytes = Files.readAllBytes(Path.of(path));
                if (isCancelled()) return false;
                setProgress(25);
                publish("Step 2/4: Checking file structure");
                UnlockBinInspector.Result result = UnlockBinInspector.verify(
                        localImei, localId, bytes, message -> publish(message));
                if (isCancelled()) return false;
                setProgress(100);
                return result.valid;
            }
            @Override protected void process(List<String> messages) {
                for (String message : messages) addLog(message);
                int pct = getProgress();
                progress.setValue(Math.round(pct / 25.0f));
                progress.setString(pct + "%");
            }
            @Override protected void done() {
                clock.stop();
                cancel.setEnabled(false);
                start.setEnabled(true);
                try {
                    boolean valid = get();
                    status.setText(valid ? "VALID — both signatures verified" : "INVALID — verification failed");
                    progress.setString(valid ? "Valid" : "Invalid");
                    addLog(status.getText());
                } catch (CancellationException ex) {
                    status.setText("Cancelled");
                    progress.setString("Cancelled");
                    addLog("Cancelled by user.");
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    status.setText("Interrupted");
                    addLog("Verification interrupted.");
                } catch (ExecutionException ex) {
                    status.setText("Error");
                    progress.setString("Error");
                    addLog("Error: " + ex.getCause().getMessage());
                }
            }
        };
        worker.execute();
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new InspectorGUI().setVisible(true));
    }
}
