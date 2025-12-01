const { app, BrowserWindow, ipcMain, dialog, shell, nativeImage, powerMonitor, Menu } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const crypto = require('crypto');
const { autoUpdater } = require('electron-updater');

// Set app name for development
app.setName('Kubeconfig Wrangler');

let mainWindow;
let backendProcess;
let serverPort = 18080;
let serverToken = '';
let isQuitting = false;
let healthCheckInterval = null;
let restartAttempts = 0;
const MAX_RESTART_ATTEMPTS = 3;
const HEALTH_CHECK_INTERVAL = 5000; // 5 seconds

// Generate a cryptographically secure random token
function generateSecurityToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Find an available port
async function findAvailablePort(startPort) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(startPort, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
    server.on('error', () => {
      resolve(findAvailablePort(startPort + 1));
    });
  });
}

// Map Node.js platform names to electron-builder directory names
function getPlatformDir() {
  switch (process.platform) {
    case 'darwin':
      return 'mac';
    case 'win32':
      return 'win';
    default:
      return 'linux';
  }
}

// Get the path to the backend binary
function getBackendPath() {
  const isDev = !app.isPackaged;
  const isWindows = process.platform === 'win32';
  const binaryName = isWindows ? 'kubeconfig-wrangler.exe' : 'kubeconfig-wrangler';

  if (isDev) {
    // In development, look for the binary in the parent bin directory
    const platformDir = getPlatformDir();
    return path.join(__dirname, '..', 'bin', platformDir, binaryName);
  } else {
    // In production, look in the resources directory
    return path.join(process.resourcesPath, 'bin', binaryName);
  }
}

// Start the Go backend server
async function startBackend() {
  const backendPath = getBackendPath();

  // Check if the backend binary exists
  if (!fs.existsSync(backendPath)) {
    console.error('Backend binary not found at:', backendPath);
    const platformDir = getPlatformDir();
    dialog.showErrorBox(
      'Backend Not Found',
      `The backend server binary was not found at:\n${backendPath}\n\nPlease build the Go backend first using:\ngo build -o bin/${platformDir}/kubeconfig-wrangler`
    );
    return false;
  }

  // Find an available port
  serverPort = await findAvailablePort(18080);

  // Generate a new security token for this session
  serverToken = generateSecurityToken();

  console.log('Starting backend server on port', serverPort);
  console.log('Backend path:', backendPath);
  console.log('Security token enabled');

  return new Promise((resolve) => {
    backendProcess = spawn(backendPath, ['serve', '--port', serverPort.toString(), '--addr', '127.0.0.1', '--token', serverToken], {
      stdio: ['ignore', 'pipe', 'pipe']
    });

    backendProcess.stdout.on('data', (data) => {
      console.log('Backend:', data.toString());
      // Check if server is ready
      if (data.toString().includes('Starting web server')) {
        setTimeout(() => resolve(true), 500); // Give it a moment to fully start
      }
    });

    backendProcess.stderr.on('data', (data) => {
      console.error('Backend error:', data.toString());
    });

    backendProcess.on('error', (error) => {
      console.error('Failed to start backend:', error);
      resolve(false);
    });

    backendProcess.on('close', (code) => {
      console.log('Backend process exited with code', code);
      backendProcess = null;

      // Auto-restart if not quitting
      if (!isQuitting && code !== 0) {
        console.log('Backend crashed unexpectedly, will attempt restart...');
        restartBackend();
      }
    });

    // Timeout in case the server doesn't output the expected message
    setTimeout(() => resolve(true), 3000);
  });
}

// Stop the backend server
function stopBackend() {
  stopHealthCheck();
  if (backendProcess) {
    console.log('Stopping backend server...');
    backendProcess.kill();
    backendProcess = null;
  }
}

// Health check function
async function checkBackendHealth() {
  return new Promise((resolve) => {
    const http = require('http');
    const req = http.request({
      hostname: '127.0.0.1',
      port: serverPort,
      path: '/',
      method: 'GET',
      timeout: 3000
    }, (res) => {
      resolve(res.statusCode === 200);
    });

    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

// Start health check monitoring
function startHealthCheck() {
  stopHealthCheck();

  healthCheckInterval = setInterval(async () => {
    if (isQuitting || !backendProcess) return;

    const isHealthy = await checkBackendHealth();

    if (!isHealthy) {
      console.log('Backend health check failed');

      // Check if the process is actually running
      if (!backendProcess) {
        console.log('Backend process not running, attempting restart...');
        await restartBackend();
      } else {
        // Process is running but not responding - might be hung
        console.log('Backend process running but not responding');
        // Give it one more chance
        const secondCheck = await checkBackendHealth();
        if (!secondCheck) {
          console.log('Backend still not responding, restarting...');
          await restartBackend();
        }
      }
    } else {
      // Reset restart attempts on successful health check
      restartAttempts = 0;
    }
  }, HEALTH_CHECK_INTERVAL);
}

// Stop health check monitoring
function stopHealthCheck() {
  if (healthCheckInterval) {
    clearInterval(healthCheckInterval);
    healthCheckInterval = null;
  }
}

// Restart backend with retry logic
async function restartBackend() {
  if (isQuitting) return false;

  if (restartAttempts >= MAX_RESTART_ATTEMPTS) {
    console.error('Max restart attempts reached, giving up');
    dialog.showErrorBox(
      'Backend Error',
      'The backend server has crashed multiple times and cannot be restarted. Please restart the application.'
    );
    return false;
  }

  restartAttempts++;
  console.log(`Attempting to restart backend (attempt ${restartAttempts}/${MAX_RESTART_ATTEMPTS})...`);

  // Kill the existing process if it's still around
  if (backendProcess) {
    try {
      backendProcess.kill('SIGKILL');
    } catch (e) {
      // Ignore errors killing the process
    }
    backendProcess = null;
  }

  // Wait a moment before restarting
  await new Promise(resolve => setTimeout(resolve, 1000));

  const success = await startBackend();

  if (success && mainWindow && !mainWindow.isDestroyed()) {
    console.log('Backend restarted successfully, reloading window...');
    mainWindow.loadURL(`http://127.0.0.1:${serverPort}`);
  }

  return success;
}

// Create the main window
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1000,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    icon: path.join(__dirname, 'build', 'icon.png'),
    title: 'Kubeconfig Wrangler',
    show: false // Don't show until ready
  });

  // Load the web interface from the backend server
  mainWindow.loadURL(`http://127.0.0.1:${serverPort}`);

  // Show window when ready
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // Handle window closed
  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Open external links in the default browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  // Handle page load failures (e.g., after sleep/resume)
  mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription) => {
    console.log('Page failed to load:', errorCode, errorDescription);
    // Retry loading after a short delay
    setTimeout(() => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        console.log('Retrying page load...');
        mainWindow.loadURL(`http://127.0.0.1:${serverPort}`);
      }
    }, 1000);
  });

  // Handle render process crashes
  mainWindow.webContents.on('render-process-gone', (event, details) => {
    console.log('Render process gone:', details.reason);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.reload();
    }
  });

  // Handle unresponsive page
  mainWindow.webContents.on('unresponsive', () => {
    console.log('Page became unresponsive, reloading...');
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.reload();
    }
  });
}

// IPC handlers for save dialog
ipcMain.handle('show-save-dialog', async (event, options) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Save Kubeconfig',
    defaultPath: options.defaultPath || 'kubeconfig.yaml',
    filters: [
      { name: 'YAML Files', extensions: ['yaml', 'yml'] },
      { name: 'All Files', extensions: ['*'] }
    ]
  });
  return result;
});

ipcMain.handle('save-file', async (event, { filePath, content }) => {
  try {
    fs.writeFileSync(filePath, content);
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// IPC handlers for open dialog (file loading)
ipcMain.handle('show-open-dialog', async (event, options) => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: options.title || 'Open File',
    defaultPath: options.defaultPath,
    filters: options.filters || [
      { name: 'YAML Files', extensions: ['yaml', 'yml'] },
      { name: 'All Files', extensions: ['*'] }
    ],
    properties: ['openFile']
  });
  return result;
});

ipcMain.handle('read-file', async (event, { filePath }) => {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    return { success: true, content };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// App lifecycle events
app.whenReady().then(async () => {
  // Set dock icon on macOS (for development)
  if (process.platform === 'darwin' && app.dock) {
    const iconPath = path.join(__dirname, 'build', 'icon.png');
    if (fs.existsSync(iconPath)) {
      const icon = nativeImage.createFromPath(iconPath);
      app.dock.setIcon(icon);
    }
  }

  const backendStarted = await startBackend();

  if (!backendStarted) {
    dialog.showErrorBox(
      'Failed to Start',
      'Could not start the backend server. The application will now close.'
    );
    app.quit();
    return;
  }

  // Start health monitoring
  startHealthCheck();

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  isQuitting = true;
  stopBackend();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  isQuitting = true;
  stopBackend();
});

app.on('will-quit', () => {
  isQuitting = true;
  stopBackend();
});

// Handle system power events
powerMonitor.on('resume', async () => {
  console.log('System resumed from sleep');
  // Give the network a moment to reconnect
  await new Promise(resolve => setTimeout(resolve, 1500));

  // Check backend health and restart if needed
  const isHealthy = await checkBackendHealth();
  if (!isHealthy) {
    console.log('Backend not responding after resume, restarting...');
    await restartBackend();
  } else if (mainWindow && !mainWindow.isDestroyed()) {
    console.log('Backend healthy, reloading window after resume...');
    mainWindow.reload();
  }
});

powerMonitor.on('unlock-screen', () => {
  console.log('Screen unlocked');
  // Check if page needs reload by trying to reload if blank
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.executeJavaScript('document.body.innerHTML.length')
      .then(length => {
        if (length === 0) {
          console.log('Page appears blank, reloading...');
          mainWindow.reload();
        }
      })
      .catch(() => {
        console.log('Could not check page content, reloading...');
        mainWindow.reload();
      });
  }
});

// ============================================
// Auto-updater configuration and event handlers
// ============================================

// Configure auto-updater
autoUpdater.autoDownload = false; // Don't download automatically, let user decide
autoUpdater.autoInstallOnAppQuit = true;

// Auto-updater event handlers
autoUpdater.on('checking-for-update', () => {
  console.log('Checking for updates...');
});

autoUpdater.on('update-available', (info) => {
  console.log('Update available:', info.version);

  dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: 'Update Available',
    message: `A new version (${info.version}) is available.`,
    detail: 'Would you like to download and install it now?',
    buttons: ['Download', 'Later'],
    defaultId: 0,
    cancelId: 1
  }).then(({ response }) => {
    if (response === 0) {
      autoUpdater.downloadUpdate();
    }
  });
});

autoUpdater.on('update-not-available', (info) => {
  console.log('No update available, current version:', info.version);
});

autoUpdater.on('error', (err) => {
  console.error('Auto-updater error:', err);
  dialog.showErrorBox('Update Error', `Failed to update: ${err.message}`);
});

autoUpdater.on('download-progress', (progressObj) => {
  const percent = Math.round(progressObj.percent);
  console.log(`Download progress: ${percent}%`);

  // Update window title to show progress
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.setTitle(`Kubeconfig Wrangler - Downloading update ${percent}%`);
  }
});

autoUpdater.on('update-downloaded', (info) => {
  console.log('Update downloaded:', info.version);

  // Reset window title
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.setTitle('Kubeconfig Wrangler');
  }

  dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: 'Update Ready',
    message: 'Update downloaded successfully!',
    detail: 'The application will restart to apply the update.',
    buttons: ['Restart Now', 'Later'],
    defaultId: 0,
    cancelId: 1
  }).then(({ response }) => {
    if (response === 0) {
      stopBackend();
      autoUpdater.quitAndInstall();
    }
  });
});

// Check for updates function
function checkForUpdates(silent = false) {
  if (app.isPackaged) {
    autoUpdater.checkForUpdates().catch(err => {
      if (!silent) {
        console.error('Failed to check for updates:', err);
      }
    });
  } else {
    console.log('Skipping update check in development mode');
    if (!silent) {
      dialog.showMessageBox(mainWindow, {
        type: 'info',
        title: 'Development Mode',
        message: 'Update checking is disabled in development mode.'
      });
    }
  }
}

// IPC handler for manual update check
ipcMain.handle('check-for-updates', async () => {
  checkForUpdates(false);
});

// IPC handler to get current version
ipcMain.handle('get-app-version', () => {
  return app.getVersion();
});

// Create application menu with update option
function createAppMenu() {
  const isMac = process.platform === 'darwin';

  const template = [
    ...(isMac ? [{
      label: app.name,
      submenu: [
        { role: 'about' },
        { type: 'separator' },
        {
          label: 'Check for Updates...',
          click: () => checkForUpdates(false)
        },
        { type: 'separator' },
        { role: 'services' },
        { type: 'separator' },
        { role: 'hide' },
        { role: 'hideOthers' },
        { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit' }
      ]
    }] : []),
    {
      label: 'File',
      submenu: [
        isMac ? { role: 'close' } : { role: 'quit' }
      ]
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' }
      ]
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },
    {
      label: 'Window',
      submenu: [
        { role: 'minimize' },
        { role: 'zoom' },
        ...(isMac ? [
          { type: 'separator' },
          { role: 'front' }
        ] : [
          { role: 'close' }
        ])
      ]
    },
    {
      label: 'Help',
      submenu: [
        ...(!isMac ? [{
          label: 'Check for Updates...',
          click: () => checkForUpdates(false)
        }, { type: 'separator' }] : []),
        {
          label: 'About Kubeconfig Wrangler',
          click: async () => {
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'About Kubeconfig Wrangler',
              message: 'Kubeconfig Wrangler',
              detail: `Version: ${app.getVersion()}\n\nManage kubeconfigs from multiple sources including Rancher and AWS EKS.`
            });
          }
        }
      ]
    }
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

// Initialize menu when app is ready (add to existing whenReady)
app.whenReady().then(() => {
  createAppMenu();

  // Check for updates silently on startup (after a short delay)
  setTimeout(() => {
    checkForUpdates(true);
  }, 5000);
});
