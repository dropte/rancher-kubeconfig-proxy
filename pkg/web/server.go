// Package web provides a web-based GUI for rancher-kubeconfig-proxy
package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"

	"github.com/rancher-kubeconfig-proxy/pkg/config"
	"github.com/rancher-kubeconfig-proxy/pkg/kubeconfig"
	"github.com/rancher-kubeconfig-proxy/pkg/rancher"
)

// Server represents the web server
type Server struct {
	addr string
	mux  *http.ServeMux
}

// ClusterInfo holds cluster information for the API
type ClusterInfo struct {
	Name        string `json:"name"`
	ID          string `json:"id"`
	State       string `json:"state"`
	Provider    string `json:"provider"`
	Description string `json:"description"`
}

// GenerateRequest represents a kubeconfig generation request
type GenerateRequest struct {
	RancherURL            string   `json:"rancherUrl"`
	Token                 string   `json:"token"`
	Username              string   `json:"username"`
	Password              string   `json:"password"`
	ClusterPrefix         string   `json:"clusterPrefix"`
	InsecureSkipTLSVerify bool     `json:"insecureSkipTlsVerify"`
	SelectedClusters      []string `json:"selectedClusters"`
}

// APIResponse represents a generic API response
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// NewServer creates a new web server
func NewServer(addr string) *Server {
	s := &Server{
		addr: addr,
		mux:  http.NewServeMux(),
	}
	s.setupRoutes()
	return s
}

// setupRoutes configures the HTTP routes
func (s *Server) setupRoutes() {
	s.mux.HandleFunc("/", s.handleIndex)
	s.mux.HandleFunc("/api/clusters", s.handleListClusters)
	s.mux.HandleFunc("/api/generate", s.handleGenerate)
}

// Start starts the web server
func (s *Server) Start() error {
	log.Printf("Starting web server on %s", s.addr)
	log.Printf("Open http://%s in your browser", s.addr)
	return http.ListenAndServe(s.addr, s.mux)
}

// handleIndex serves the main HTML page
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	tmpl, err := template.New("index").Parse(indexHTML)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Error executing template: %v", err)
	}
}

// handleListClusters handles the cluster listing API endpoint
func (s *Server) handleListClusters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, APIResponse{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	var req GenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	cfg := &config.Config{
		RancherURL:            req.RancherURL,
		Token:                 req.Token,
		Username:              req.Username,
		Password:              req.Password,
		InsecureSkipTLSVerify: req.InsecureSkipTLSVerify,
	}

	if err := cfg.Validate(); err != nil {
		s.writeJSON(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Configuration error: %v", err),
		})
		return
	}

	client, err := rancher.NewClient(cfg)
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to create Rancher client: %v", err),
		})
		return
	}

	clusters, err := client.ListClusters()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to list clusters: %v", err),
		})
		return
	}

	clusterInfos := make([]ClusterInfo, len(clusters))
	for i, c := range clusters {
		clusterInfos[i] = ClusterInfo{
			Name:        c.Name,
			ID:          c.ID,
			State:       c.State,
			Provider:    c.Provider,
			Description: c.Description,
		}
	}

	s.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    clusterInfos,
	})
}

// handleGenerate handles the kubeconfig generation API endpoint
func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, APIResponse{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	var req GenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	cfg := &config.Config{
		RancherURL:            req.RancherURL,
		Token:                 req.Token,
		Username:              req.Username,
		Password:              req.Password,
		ClusterPrefix:         req.ClusterPrefix,
		InsecureSkipTLSVerify: req.InsecureSkipTLSVerify,
	}

	if err := cfg.Validate(); err != nil {
		s.writeJSON(w, http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Configuration error: %v", err),
		})
		return
	}

	client, err := rancher.NewClient(cfg)
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to create Rancher client: %v", err),
		})
		return
	}

	// Get list of clusters to determine which to include
	clusters, err := client.ListClusters()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to list clusters: %v", err),
		})
		return
	}

	// Build selected cluster set
	selectedSet := make(map[string]bool)
	for _, name := range req.SelectedClusters {
		selectedSet[name] = true
	}

	// Fetch kubeconfigs for selected clusters in parallel
	kubeconfigs := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	errors := make([]string, 0)

	for _, cluster := range clusters {
		// Skip if not selected (when selection is provided)
		if len(selectedSet) > 0 && !selectedSet[cluster.Name] {
			continue
		}

		// Skip inactive clusters
		if cluster.State != "active" {
			continue
		}

		wg.Add(1)
		go func(c rancher.Cluster) {
			defer wg.Done()

			kubeconfig, err := client.GetClusterKubeconfig(&c)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Sprintf("%s: %v", c.Name, err))
				mu.Unlock()
				return
			}

			mu.Lock()
			kubeconfigs[c.Name] = kubeconfig
			mu.Unlock()
		}(cluster)
	}

	wg.Wait()

	if len(kubeconfigs) == 0 {
		errMsg := "No kubeconfigs retrieved"
		if len(errors) > 0 {
			errMsg = fmt.Sprintf("Failed to get kubeconfigs: %v", errors)
		}
		s.writeJSON(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   errMsg,
		})
		return
	}

	// Generate merged kubeconfig
	generator := kubeconfig.NewGenerator(cfg.ClusterPrefix)
	kubeconfigData, err := generator.Generate(kubeconfigs)
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to generate kubeconfig: %v", err),
		})
		return
	}

	// Return as downloadable file
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", "attachment; filename=kubeconfig.yaml")
	if _, err := w.Write(kubeconfigData); err != nil {
		log.Printf("Error writing kubeconfig response: %v", err)
	}
}

// writeJSON writes a JSON response
func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// indexHTML is the embedded HTML template for the web interface
const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rancher Kubeconfig Generator</title>
    <style>
        :root {
            --bg-primary: #1e1e1e;
            --bg-secondary: #252526;
            --bg-tertiary: #2d2d30;
            --bg-hover: #3c3c3c;
            --bg-active: #094771;
            --text-primary: #cccccc;
            --text-secondary: #969696;
            --text-bright: #ffffff;
            --accent: #0078d4;
            --accent-hover: #1c8ae6;
            --success: #4ec9b0;
            --warning: #dcdcaa;
            --error: #f14c4c;
            --border: #3c3c3c;
            --input-bg: #3c3c3c;
            --sidebar-width: 320px;
        }

        @media (prefers-color-scheme: light) {
            :root {
                --bg-primary: #ffffff;
                --bg-secondary: #f3f3f3;
                --bg-tertiary: #e8e8e8;
                --bg-hover: #e0e0e0;
                --bg-active: #cce4f7;
                --text-primary: #333333;
                --text-secondary: #666666;
                --text-bright: #000000;
                --accent: #0078d4;
                --accent-hover: #106ebe;
                --success: #107c10;
                --warning: #ca8a00;
                --error: #d32f2f;
                --border: #d4d4d4;
                --input-bg: #ffffff;
            }
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 13px;
            line-height: 1.4;
            height: 100vh;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        /* Toolbar */
        .toolbar {
            height: 38px;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            padding: 0 12px;
            gap: 8px;
            -webkit-app-region: drag;
            flex-shrink: 0;
        }

        .toolbar-title {
            font-weight: 600;
            font-size: 13px;
            color: var(--text-bright);
            margin-right: auto;
        }

        .toolbar-btn {
            -webkit-app-region: no-drag;
            background: var(--accent);
            color: white;
            border: none;
            padding: 5px 12px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .toolbar-btn:hover {
            background: var(--accent-hover);
        }

        .toolbar-btn:disabled {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            cursor: not-allowed;
        }

        .toolbar-btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }

        .toolbar-btn-secondary:hover {
            background: var(--bg-hover);
        }

        /* Main Layout */
        .main-container {
            display: flex;
            flex: 1;
            overflow: hidden;
        }

        /* Sidebar */
        .sidebar {
            width: var(--sidebar-width);
            background: var(--bg-secondary);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            flex-shrink: 0;
        }

        .sidebar-header {
            padding: 12px;
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border);
        }

        .sidebar-content {
            flex: 1;
            overflow-y: auto;
            padding: 12px;
        }

        .form-section {
            margin-bottom: 16px;
        }

        .form-section-title {
            font-size: 11px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }

        .form-group {
            margin-bottom: 12px;
        }

        .form-group label {
            display: block;
            font-size: 12px;
            color: var(--text-secondary);
            margin-bottom: 4px;
        }

        .form-group input[type="text"],
        .form-group input[type="password"],
        .form-group input[type="url"] {
            width: 100%;
            padding: 6px 8px;
            background: var(--input-bg);
            border: 1px solid var(--border);
            border-radius: 3px;
            color: var(--text-primary);
            font-size: 12px;
            font-family: inherit;
        }

        .form-group input:focus {
            outline: none;
            border-color: var(--accent);
        }

        .form-group input::placeholder {
            color: var(--text-secondary);
        }

        /* Segmented Control */
        .segmented-control {
            display: flex;
            background: var(--bg-tertiary);
            border-radius: 4px;
            padding: 2px;
            margin-bottom: 12px;
        }

        .segment-btn {
            flex: 1;
            padding: 5px 8px;
            border: none;
            background: transparent;
            color: var(--text-secondary);
            font-size: 11px;
            font-weight: 500;
            cursor: pointer;
            border-radius: 3px;
            transition: all 0.15s;
        }

        .segment-btn:hover {
            color: var(--text-primary);
        }

        .segment-btn.active {
            background: var(--accent);
            color: white;
        }

        .auth-panel {
            display: none;
        }

        .auth-panel.active {
            display: block;
        }

        /* Checkbox */
        .checkbox-row {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 4px 0;
        }

        .checkbox-row input[type="checkbox"] {
            width: 14px;
            height: 14px;
            accent-color: var(--accent);
        }

        .checkbox-row label {
            font-size: 12px;
            color: var(--text-primary);
            cursor: pointer;
            margin: 0;
        }

        /* Main Content */
        .content {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        .content-header {
            padding: 12px 16px;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .content-title {
            font-weight: 600;
            font-size: 12px;
            color: var(--text-bright);
        }

        .cluster-count {
            font-size: 11px;
            color: var(--text-secondary);
            background: var(--bg-tertiary);
            padding: 2px 8px;
            border-radius: 10px;
        }

        /* Table */
        .table-container {
            flex: 1;
            overflow: auto;
        }

        .cluster-table {
            width: 100%;
            border-collapse: collapse;
        }

        .cluster-table th {
            position: sticky;
            top: 0;
            background: var(--bg-tertiary);
            text-align: left;
            padding: 8px 12px;
            font-size: 11px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border);
        }

        .cluster-table th:first-child {
            width: 40px;
            text-align: center;
        }

        .cluster-table td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }

        .cluster-table tr:hover {
            background: var(--bg-hover);
        }

        .cluster-table tr.selected {
            background: var(--bg-active);
        }

        .cluster-table td:first-child {
            text-align: center;
        }

        .cluster-name {
            font-weight: 500;
            color: var(--text-bright);
        }

        .cluster-id {
            font-size: 11px;
            color: var(--text-secondary);
            font-family: 'SF Mono', Monaco, 'Courier New', monospace;
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: 500;
        }

        .status-badge::before {
            content: '';
            width: 6px;
            height: 6px;
            border-radius: 50%;
        }

        .status-active {
            background: rgba(78, 201, 176, 0.15);
            color: var(--success);
        }

        .status-active::before {
            background: var(--success);
        }

        .status-inactive {
            background: rgba(220, 220, 170, 0.15);
            color: var(--warning);
        }

        .status-inactive::before {
            background: var(--warning);
        }

        .status-error {
            background: rgba(241, 76, 76, 0.15);
            color: var(--error);
        }

        .status-error::before {
            background: var(--error);
        }

        /* Empty State */
        .empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: var(--text-secondary);
            text-align: center;
            padding: 40px;
        }

        .empty-state-icon {
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }

        .empty-state-title {
            font-size: 16px;
            font-weight: 500;
            color: var(--text-primary);
            margin-bottom: 8px;
        }

        .empty-state-text {
            font-size: 13px;
            max-width: 300px;
        }

        /* Loading */
        .loading-overlay {
            display: none;
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.5);
            align-items: center;
            justify-content: center;
            z-index: 100;
        }

        .loading-overlay.visible {
            display: flex;
        }

        .loading-spinner {
            width: 32px;
            height: 32px;
            border: 3px solid var(--border);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Status Bar */
        .status-bar {
            height: 24px;
            background: var(--bg-tertiary);
            border-top: 1px solid var(--border);
            display: flex;
            align-items: center;
            padding: 0 12px;
            font-size: 11px;
            color: var(--text-secondary);
            flex-shrink: 0;
        }

        .status-bar-item {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .status-bar-item::after {
            content: '|';
            margin: 0 8px;
            opacity: 0.3;
        }

        .status-bar-item:last-child::after {
            display: none;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--text-secondary);
        }

        .status-dot.connected {
            background: var(--success);
        }

        .status-dot.error {
            background: var(--error);
        }

        /* Toast Notification */
        .toast {
            position: fixed;
            bottom: 40px;
            left: 50%;
            transform: translateX(-50%) translateY(100px);
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 12px 20px;
            font-size: 13px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            z-index: 1000;
            opacity: 0;
            transition: all 0.3s ease;
        }

        .toast.visible {
            transform: translateX(-50%) translateY(0);
            opacity: 1;
        }

        .toast.success {
            border-left: 3px solid var(--success);
        }

        .toast.error {
            border-left: 3px solid var(--error);
        }

        .hidden {
            display: none !important;
        }
    </style>
</head>
<body>
    <!-- Toolbar -->
    <div class="toolbar">
        <span class="toolbar-title">Rancher Kubeconfig Generator</span>
        <button class="toolbar-btn toolbar-btn-secondary" id="refreshBtn" onclick="fetchClusters()" disabled>
            ↻ Refresh
        </button>
        <button class="toolbar-btn" id="generateBtn" onclick="generateKubeconfig()" disabled>
            ⬇ Generate Kubeconfig
        </button>
    </div>

    <!-- Main Container -->
    <div class="main-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="sidebar-header">Connection Settings</div>
            <div class="sidebar-content">
                <div class="form-section">
                    <div class="form-group">
                        <label>Rancher URL</label>
                        <input type="url" id="rancherUrl" placeholder="https://rancher.example.com">
                    </div>
                </div>

                <div class="form-section">
                    <div class="form-section-title">Authentication</div>
                    <div class="segmented-control">
                        <button class="segment-btn active" onclick="switchAuthMethod('token', this)">API Token</button>
                        <button class="segment-btn" onclick="switchAuthMethod('password', this)">Password</button>
                    </div>

                    <div id="authToken" class="auth-panel active">
                        <div class="form-group">
                            <label>API Token</label>
                            <input type="password" id="token" placeholder="token-xxxxx:yyyyyyy">
                        </div>
                    </div>

                    <div id="authPassword" class="auth-panel">
                        <div class="form-group">
                            <label>Username</label>
                            <input type="text" id="username" placeholder="admin">
                        </div>
                        <div class="form-group">
                            <label>Password</label>
                            <input type="password" id="password" placeholder="••••••••">
                        </div>
                    </div>
                </div>

                <div class="form-section">
                    <div class="form-section-title">Options</div>
                    <div class="form-group">
                        <label>Context Prefix</label>
                        <input type="text" id="clusterPrefix" placeholder="Optional prefix">
                    </div>
                    <div class="checkbox-row">
                        <input type="checkbox" id="insecureSkipTls">
                        <label for="insecureSkipTls">Skip TLS verification</label>
                    </div>
                </div>

                <button class="toolbar-btn" style="width: 100%; justify-content: center;" id="connectBtn" onclick="fetchClusters()">
                    Connect to Rancher
                </button>
            </div>
        </div>

        <!-- Content -->
        <div class="content">
            <div class="content-header">
                <span class="content-title">Clusters</span>
                <span class="cluster-count" id="clusterCount">0 clusters</span>
            </div>

            <div class="table-container" id="tableContainer">
                <!-- Empty State -->
                <div class="empty-state" id="emptyState">
                    <div class="empty-state-icon">☁</div>
                    <div class="empty-state-title">No clusters loaded</div>
                    <div class="empty-state-text">Enter your Rancher connection details and click "Connect to Rancher" to get started.</div>
                </div>

                <!-- Cluster Table -->
                <table class="cluster-table hidden" id="clusterTable">
                    <thead>
                        <tr>
                            <th><input type="checkbox" id="selectAll" onchange="toggleSelectAll()"></th>
                            <th>Name</th>
                            <th>ID</th>
                            <th>Provider</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody id="clusterTableBody">
                    </tbody>
                </table>
            </div>

            <!-- Loading Overlay -->
            <div class="loading-overlay" id="loadingOverlay">
                <div class="loading-spinner"></div>
            </div>
        </div>
    </div>

    <!-- Status Bar -->
    <div class="status-bar">
        <div class="status-bar-item">
            <span class="status-dot" id="connectionStatus"></span>
            <span id="connectionText">Not connected</span>
        </div>
        <div class="status-bar-item" id="selectionStatus">
            0 selected
        </div>
    </div>

    <!-- Toast -->
    <div class="toast" id="toast"></div>

    <script>
        let clusters = [];
        let currentAuthMethod = 'token';
        let isConnected = false;

        function switchAuthMethod(method, btn) {
            currentAuthMethod = method;
            document.querySelectorAll('.segment-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('authToken').classList.toggle('active', method === 'token');
            document.getElementById('authPassword').classList.toggle('active', method === 'password');
        }

        function getAuthCredentials() {
            if (currentAuthMethod === 'token') {
                return { token: document.getElementById('token').value.trim(), username: '', password: '' };
            }
            return {
                token: '',
                username: document.getElementById('username').value.trim(),
                password: document.getElementById('password').value.trim()
            };
        }

        function showToast(message, type = 'success') {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = 'toast ' + type + ' visible';
            setTimeout(() => toast.classList.remove('visible'), 3000);
        }

        function setLoading(loading) {
            document.getElementById('loadingOverlay').classList.toggle('visible', loading);
            document.getElementById('connectBtn').disabled = loading;
        }

        function updateConnectionStatus(connected, text) {
            isConnected = connected;
            document.getElementById('connectionStatus').classList.toggle('connected', connected);
            document.getElementById('connectionStatus').classList.toggle('error', !connected && text.includes('Error'));
            document.getElementById('connectionText').textContent = text;
            document.getElementById('refreshBtn').disabled = !connected;
        }

        function updateSelectionStatus() {
            const selected = getSelectedClusters();
            document.getElementById('selectionStatus').textContent = selected.length + ' selected';
            document.getElementById('generateBtn').disabled = selected.length === 0;
        }

        function getStatusClass(state) {
            if (state === 'active') return 'status-active';
            if (state === 'error' || state === 'unavailable') return 'status-error';
            return 'status-inactive';
        }

        async function fetchClusters() {
            const rancherUrl = document.getElementById('rancherUrl').value.trim();
            const creds = getAuthCredentials();
            const insecureSkipTls = document.getElementById('insecureSkipTls').checked;

            if (!rancherUrl) {
                showToast('Please enter the Rancher URL', 'error');
                return;
            }

            if (currentAuthMethod === 'token' && !creds.token) {
                showToast('Please enter your API token', 'error');
                return;
            }

            if (currentAuthMethod === 'password' && (!creds.username || !creds.password)) {
                showToast('Please enter username and password', 'error');
                return;
            }

            setLoading(true);
            updateConnectionStatus(false, 'Connecting...');

            try {
                const response = await fetch('/api/clusters', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        rancherUrl, token: creds.token, username: creds.username,
                        password: creds.password, insecureSkipTlsVerify: insecureSkipTls
                    })
                });

                const result = await response.json();

                if (!result.success) {
                    updateConnectionStatus(false, 'Connection failed');
                    showToast(result.error || 'Failed to connect', 'error');
                    return;
                }

                clusters = result.data || [];
                renderClusterTable();
                updateConnectionStatus(true, 'Connected to ' + new URL(rancherUrl).hostname);
                showToast('Found ' + clusters.length + ' cluster(s)', 'success');

            } catch (error) {
                updateConnectionStatus(false, 'Error: ' + error.message);
                showToast('Connection failed: ' + error.message, 'error');
            } finally {
                setLoading(false);
            }
        }

        function renderClusterTable() {
            const tbody = document.getElementById('clusterTableBody');
            const table = document.getElementById('clusterTable');
            const emptyState = document.getElementById('emptyState');

            tbody.innerHTML = '';

            if (clusters.length === 0) {
                table.classList.add('hidden');
                emptyState.classList.remove('hidden');
                document.getElementById('clusterCount').textContent = '0 clusters';
                return;
            }

            table.classList.remove('hidden');
            emptyState.classList.add('hidden');
            document.getElementById('clusterCount').textContent = clusters.length + ' cluster' + (clusters.length !== 1 ? 's' : '');

            clusters.forEach((cluster, index) => {
                const tr = document.createElement('tr');
                const isActive = cluster.state === 'active';
                tr.innerHTML = ` + "`" + `
                    <td><input type="checkbox" id="cluster-${index}" ${isActive ? 'checked' : ''} ${!isActive ? 'disabled' : ''} onchange="onClusterSelect(${index})"></td>
                    <td><span class="cluster-name">${escapeHtml(cluster.name)}</span></td>
                    <td><span class="cluster-id">${escapeHtml(cluster.id)}</span></td>
                    <td>${escapeHtml(cluster.provider || '—')}</td>
                    <td><span class="status-badge ${getStatusClass(cluster.state)}">${escapeHtml(cluster.state)}</span></td>
                ` + "`" + `;
                if (isActive) tr.classList.add('selected');
                tbody.appendChild(tr);
            });

            updateSelectAll();
            updateSelectionStatus();
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text || '';
            return div.innerHTML;
        }

        function onClusterSelect(index) {
            const checkbox = document.getElementById('cluster-' + index);
            const row = checkbox.closest('tr');
            row.classList.toggle('selected', checkbox.checked);
            updateSelectAll();
            updateSelectionStatus();
        }

        function toggleSelectAll() {
            const selectAll = document.getElementById('selectAll').checked;
            clusters.forEach((cluster, index) => {
                if (cluster.state === 'active') {
                    const checkbox = document.getElementById('cluster-' + index);
                    checkbox.checked = selectAll;
                    checkbox.closest('tr').classList.toggle('selected', selectAll);
                }
            });
            updateSelectionStatus();
        }

        function updateSelectAll() {
            const activeClusters = clusters.filter(c => c.state === 'active');
            const checkedCount = activeClusters.filter((_, i) => {
                const idx = clusters.indexOf(activeClusters[i]);
                const cb = document.getElementById('cluster-' + clusters.findIndex(c => c === activeClusters[i]));
                return cb && cb.checked;
            }).length;
            document.getElementById('selectAll').checked = checkedCount === activeClusters.length && activeClusters.length > 0;
        }

        function getSelectedClusters() {
            return clusters.filter((cluster, index) => {
                const cb = document.getElementById('cluster-' + index);
                return cb && cb.checked;
            }).map(c => c.name);
        }

        async function generateKubeconfig() {
            const rancherUrl = document.getElementById('rancherUrl').value.trim();
            const clusterPrefix = document.getElementById('clusterPrefix').value;
            const insecureSkipTls = document.getElementById('insecureSkipTls').checked;
            const selectedClusters = getSelectedClusters();
            const creds = getAuthCredentials();

            if (selectedClusters.length === 0) {
                showToast('Please select at least one cluster', 'error');
                return;
            }

            const btn = document.getElementById('generateBtn');
            btn.disabled = true;
            btn.textContent = '⏳ Generating...';

            try {
                const response = await fetch('/api/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        rancherUrl, token: creds.token, username: creds.username,
                        password: creds.password, clusterPrefix, insecureSkipTlsVerify: insecureSkipTls,
                        selectedClusters
                    })
                });

                if (response.headers.get('Content-Type')?.includes('application/json')) {
                    const result = await response.json();
                    showToast(result.error || 'Generation failed', 'error');
                    return;
                }

                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'kubeconfig.yaml';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();

                showToast('Kubeconfig downloaded successfully!', 'success');

            } catch (error) {
                showToast('Failed to generate: ' + error.message, 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = '⬇ Generate Kubeconfig';
                updateSelectionStatus();
            }
        }
    </script>
</body>
</html>`
