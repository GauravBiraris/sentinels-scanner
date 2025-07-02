import React, { useState, useRef } from 'react';
import { Shield, Upload, Search, AlertTriangle, CheckCircle, X, FileText, Eye, Download, RefreshCw } from 'lucide-react';
import AppSecurityAnalyzer from './components/AppSecurityAnalyzer';


// API utility functions
const API_BASE_URL = 'https://sentinel-api-aryc.onrender.com';

const generateFingerprint = async (file, appInfo) => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('appId', appInfo.appId);
  formData.append('appName', appInfo.appName);
  formData.append('version', appInfo.version);
  formData.append('packageName', appInfo.packageName || appInfo.appId);

  const response = await fetch(`${API_BASE_URL}/api/fingerprints/generate`, {
    method: 'POST',
    body: formData
  });

  const data = await response.json();
  if (!data.success) {
    throw new Error(data.error || 'Failed to generate fingerprint');
  }
  return data.fingerprint;
};

const verifyApp = async (overallHash, appId, packageName, scannerInfo = {}) => {
  const response = await fetch(`${API_BASE_URL}/api/fingerprints/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      overallHash,
      appId,
      packageName,
      scannerInfo
    })
  });

  const data = await response.json();
  if (!data.success) {
    throw new Error(data.error || 'Verification failed');
  }
  return data;
};

// Credibility analysis function
const analyzeAppCredibility = (appData) => {
  const risks = [];
  const warnings = [];
  const info = [];
  
  // Check for suspicious permissions
  const suspiciousPerms = [
    'SEND_SMS', 'READ_SMS', 'RECEIVE_SMS',
    'WRITE_EXTERNAL_STORAGE', 'READ_EXTERNAL_STORAGE',
    'CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION',
    'READ_CONTACTS', 'WRITE_CONTACTS',
    'READ_CALL_LOG', 'WRITE_CALL_LOG',
    'SYSTEM_ALERT_WINDOW', 'WRITE_SETTINGS'
  ];
  
  // Check for financial data requests
  const financialKeywords = [
    'credit card', 'debit card', 'cvv', 'card number',
    'bank account', 'account number', 'routing number',
    'payment', 'billing', 'transaction'
  ];
  
  // Check for identity theft risks
  const identityKeywords = [
    'aadhar', 'aadhaar', 'passport number', 'ssn',
    'social security', 'driver license', 'pan card'
  ];
  
  // Check for social media access
  const socialApps = [
    'whatsapp', 'telegram', 'instagram', 'facebook',
    'twitter', 'youtube', 'snapchat', 'linkedin'
  ];

  // Analyze permissions
  if (appData.permissions) {
    const hasRiskyPerms = suspiciousPerms.some(perm => 
      appData.permissions.includes(perm)
    );
    if (hasRiskyPerms) {
      warnings.push('App requests sensitive device permissions');
    }
  }

  // Analyze manifest or code content
  const content = JSON.stringify(appData).toLowerCase();
  
  financialKeywords.forEach(keyword => {
    if (content.includes(keyword)) {
      risks.push(`Requests financial information: ${keyword}`);
    }
  });
  
  identityKeywords.forEach(keyword => {
    if (content.includes(keyword)) {
      risks.push(`Requests identity information: ${keyword}`);
    }
  });
  
  socialApps.forEach(app => {
    if (content.includes(app)) {
      warnings.push(`May access ${app} data`);
    }
  });

  // Check for developer information
  if (!appData.developer || !appData.contact) {
    warnings.push('Missing or incomplete developer contact information');
  }

  // Check for secure connections
  if (content.includes('http://') && !content.includes('https://')) {
    risks.push('Uses insecure HTTP connections');
  }

  const riskLevel = risks.length > 0 ? 'HIGH' : 
                   warnings.length > 2 ? 'MEDIUM' : 'LOW';

  return {
    riskLevel,
    risks,
    warnings,
    info,
    score: Math.max(0, 100 - (risks.length * 30) - (warnings.length * 10))
  };
};

// Mock APK/IPA parser (simplified)
const parseAppFile = async (file) => {
  // This is a simplified mock parser
  // In a real implementation, you'd use libraries like apk-parser, ipa-extract
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        packageName: 'com.example.app',
        appName: file.name.replace(/\.(apk|ipa)$/, ''),
        version: '1.0.0',
        permissions: ['CAMERA', 'LOCATION', 'STORAGE'],
        developer: 'Unknown Developer',
        contact: null,
        size: file.size,
        activities: ['MainActivity', 'LoginActivity'],
        services: ['BackgroundService'],
        receivers: ['NotificationReceiver']
      });
    }, 2000);
  });
};

const SentinelsScanner = () => {
  const [activeTab, setActiveTab] = useState('fingerprint');
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [credibilityResult, setCredibilityResult] = useState(null);
  const fileInputRef = useRef(null);

  // App info for fingerprint generation
  const [appInfo, setAppInfo] = useState({
    appId: '',
    appName: '',
    version: '',
    packageName: ''
  });

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      const fileExt = selectedFile.name.toLowerCase();
      if (!fileExt.endsWith('.apk') && !fileExt.endsWith('.ipa')) {
        setError('Please select an APK or IPA file');
        return;
      }
      setFile(selectedFile);
      setError(null);
      setResult(null);
      setCredibilityResult(null);

      // Auto-fill app info from filename
      if (activeTab === 'fingerprint') {
        const baseName = selectedFile.name.replace(/\.(apk|ipa)$/, '');
        setAppInfo(prev => ({
          ...prev,
          appName: baseName,
          appId: prev.appId || `com.example.${baseName.toLowerCase().replace(/\s+/g, '')}`
        }));
      }
    }
  };

  const handleInputChange = (e) => {
    setAppInfo({
      ...appInfo,
      [e.target.name]: e.target.value
    });
  };

  const generateAndVerifyFingerprint = async () => {
    if (!file || !appInfo.appId || !appInfo.appName || !appInfo.version) {
      setError('Please fill all required fields and select a file');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      // Generate fingerprint
      const fingerprint = await generateFingerprint(file, appInfo);
      
      // Verify against database
      const verification = await verifyApp(
        fingerprint.overallHash,
        fingerprint.appId,
        fingerprint.packageName,
        { source: 'sentinels_scanner', timestamp: new Date().toISOString() }
      );

      setResult({
        fingerprint,
        verification,
        isAuthentic: verification.isAuthentic
      });

    } catch (err) {
      setError('Error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const analyzeCredibility = async () => {
    if (!file) {
      setError('Please select an APK or IPA file');
      return;
    }

    setLoading(true);
    setError(null);
    setCredibilityResult(null);

    try {
      // Parse the app file
      const appData = await parseAppFile(file);
      
      // Analyze credibility
      const analysis = analyzeAppCredibility(appData);
      
      setCredibilityResult({
        appData,
        analysis
      });

    } catch (err) {
      setError('Error analyzing app: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const clearAll = () => {
    setFile(null);
    setResult(null);
    setCredibilityResult(null);
    setError(null);
    setAppInfo({
      appId: '',
      appName: '',
      version: '',
      packageName: ''
    });
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="min-h-screen bg-yellow-50">
      {/* Header */}
      <header className="shadow-lg" style={{ backgroundColor: '#CD853F' }}>
        <div className="max-w-4xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              
              <Shield className="w-8 h-8 text-white" style={{ display: 'none' }} />
              <h1 className="text-2xl font-bold text-white">Sentinels</h1>
              
            </div>
            <img src="/logo.svg" alt="Sentinels Logo" className="max-h-screen w-12 h-12" onError={(e) => {
                e.target.style.display = 'none';
                e.target.nextSibling.style.display = 'inline';
              }} />
            <p className="text-white text-opacity-90 text-sm hidden sm:block">
              Clone & Fake App Scanner
            </p>
          </div>
        </div>
      </header>

      <div className="max-w-4xl mx-auto p-4 space-y-6">
        {/* Tab Navigation */}
        <div className="flex bg-white rounded-lg shadow-md overflow-hidden mt-6">
          <button
            onClick={() => setActiveTab('fingerprint')}
            className={`flex-1 py-4 px-6 font-medium text-center transition-colors duration-200 ${
              activeTab === 'fingerprint'
                ? 'bg-teal-500 text-white'
                : 'bg-white text-gray-600 hover:bg-gray-100'
            }`}
          >
            <Search className="w-5 h-5 inline mr-2" />
            Fingerprint Scan
          </button>
          <button
            onClick={() => setActiveTab('credibility')}
            className={`flex-1 py-4 px-6 font-medium text-center transition-colors duration-200 ${
              activeTab === 'credibility'
                ? 'bg-teal-500 text-white'
                : 'bg-white text-gray-600 hover:bg-gray-100'
            }`}
          >
            <Eye className="w-5 h-5 inline mr-2" />
            Credibility Check
          </button>
        </div>

        {/* File Upload Section */}
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-xl font-semibold mb-4 text-teal-700 text-center">
            Upload App File
          </h2>
          
          <div className="border-2 border-dashed border-teal-300 rounded-lg p-8 text-center transition-colors hover:border-teal-400">
            
            <img src="/logo.svg" alt="Sentinels Logo" className="max-h-screen w-13 h-13 text-center" onError={(e) => {
                e.target.style.display = 'none';
                e.target.nextSibling.style.display = 'inline';
              }} />
            <p className="text-gray-600 mb-4 text-center">
              Drag and drop your APK or IPA file here, or click to browse
            </p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".apk,.ipa"
              onChange={handleFileChange}
              className="hidden"
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              className="px-6 py-3 rounded-lg text-white font-medium hover:opacity-90 transition-opacity"
              style={{ backgroundColor: '#CD853F' }}
            >
              Choose File
            </button>
          </div>

          {file && (
            <div className="mt-4 p-4 bg-teal-50 rounded-lg flex items-center justify-between">
              <div className="flex items-center">
                <FileText className="w-5 h-5 mr-3 text-teal-600" />
                <div>
                  <span className="font-medium text-gray-800 block">{file.name}</span>
                  <span className="text-sm text-gray-500">
                    {(file.size / 1024 / 1024).toFixed(2)} MB
                  </span>
                </div>
              </div>
              <button
                onClick={clearAll}
                className="text-gray-500 hover:text-red-500 transition-colors p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          )}
        </div>

        {/* Fingerprint Scan Tab */}
        {activeTab === 'fingerprint' && (
          <div className="bg-white rounded-lg shadow-md p-6">
            <h3 className="text-lg font-semibold mb-6 text-teal-700 text-center">
              App Information
            </h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
              <div>
                <label className="block text-sm font-medium mb-2 text-gray-700">
                  App ID/Package Name *
                </label>
                <input
                  type="text"
                  name="appId"
                  value={appInfo.appId}
                  onChange={handleInputChange}
                  placeholder="com.example.myapp"
                  className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-transparent"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2 text-gray-700">
                  App Name *
                </label>
                <input
                  type="text"
                  name="appName"
                  value={appInfo.appName}
                  onChange={handleInputChange}
                  placeholder="My Awesome App"
                  className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-transparent"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2 text-gray-700">
                  Version *
                </label>
                <input
                  type="text"
                  name="version"
                  value={appInfo.version}
                  onChange={handleInputChange}
                  placeholder="1.0.0"
                  className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-transparent"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2 text-gray-700">
                  Package Name (optional)
                </label>
                <input
                  type="text"
                  name="packageName"
                  value={appInfo.packageName}
                  onChange={handleInputChange}
                  placeholder="Leave empty to use App ID"
                  className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-transparent"
                />
              </div>
            </div>

            <button
              onClick={generateAndVerifyFingerprint}
              disabled={loading || !file}
              className="w-full py-4 px-6 bg-teal-500 hover:bg-teal-600 text-white font-medium rounded-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center transition-colors"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-5 h-5 mr-2 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Search className="w-5 h-5 mr-2" />
                  Scan for Authenticity
                </>
              )}
            </button>
          </div>
        )}

        {/* Credibility Check Tab */}
        {activeTab === 'credibility' && (
          <AppSecurityAnalyzer />
        )}

        {/* Error Display */}
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <div className="flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-red-500 mr-2" />
              <span className="text-red-700 font-medium">{error}</span>
            </div>
          </div>
        )}

        {/* Fingerprint Results */}
        {result && activeTab === 'fingerprint' && (
          <div className="bg-white rounded-lg shadow-md p-6">
            <h3 className="text-lg font-semibold mb-6 text-teal-700 text-center">
              Scan Results
            </h3>
            
            <div className={`p-6 rounded-lg mb-6 text-center ${
              result.isAuthentic 
                ? 'bg-green-50 border border-green-200' 
                : 'bg-red-50 border border-red-200'
            }`}>
              <div className="flex items-center justify-center mb-4">
                {result.isAuthentic ? (
                  <CheckCircle className="w-8 h-8 text-green-500 mr-3" />
                ) : (
                  <AlertTriangle className="w-8 h-8 text-red-500 mr-3" />
                )}
                <span className={`font-bold text-lg ${
                  result.isAuthentic ? 'text-green-700' : 'text-red-700'
                }`}>
                  {result.verification.message}
                </span>
              </div>
              
              {result.verification.matchDetails && (
                <div className="mt-4 text-sm bg-white p-4 rounded border">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="text-left">
                      <p><strong>App:</strong> {result.verification.matchDetails.appName}</p>
                      <p><strong>Version:</strong> {result.verification.matchDetails.version}</p>
                    </div>
                    <div className="text-left">
                      <p><strong>Developer:</strong> {result.verification.matchDetails.developer}</p>
                      <p><strong>Confidence:</strong> {(result.verification.matchDetails.confidence * 100).toFixed(1)}%</p>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="bg-gray-50 p-4 rounded-lg">
              <h4 className="font-medium mb-3 text-center">Fingerprint Details</h4>
              <div className="text-sm text-gray-600 space-y-2">
                <p className="break-all text-center">
                  <strong>Hash:</strong> {result.fingerprint.overallHash}
                </p>
                <p className="text-center">
                  <strong>File Type:</strong> {result.fingerprint.fileType || 'Unknown'}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Credibility Results */}
        {credibilityResult && activeTab === 'credibility' && (
          <div className="bg-white rounded-lg shadow-md p-6">
            <h3 className="text-lg font-semibold mb-6 text-teal-700 text-center">
              Credibility Analysis Results
            </h3>
            
            {/* Risk Score */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <div className="text-center bg-gray-50 p-4 rounded-lg">
                <div className={`text-4xl font-bold ${
                  credibilityResult.analysis.riskLevel === 'HIGH' ? 'text-red-500' :
                  credibilityResult.analysis.riskLevel === 'MEDIUM' ? 'text-yellow-500' :
                  'text-green-500'
                }`}>
                  {credibilityResult.analysis.score}
                </div>
                <div className="text-sm text-gray-600 mt-1">Safety Score</div>
              </div>
              <div className="text-center bg-gray-50 p-4 rounded-lg">
                <div className={`text-2xl font-semibold ${
                  credibilityResult.analysis.riskLevel === 'HIGH' ? 'text-red-500' :
                  credibilityResult.analysis.riskLevel === 'MEDIUM' ? 'text-yellow-500' :
                  'text-green-500'
                }`}>
                  {credibilityResult.analysis.riskLevel}
                </div>
                <div className="text-sm text-gray-600 mt-1">Risk Level</div>
              </div>
              <div className="text-center bg-gray-50 p-4 rounded-lg">
                <div className="text-2xl font-semibold text-gray-700">
                  {credibilityResult.analysis.risks.length + credibilityResult.analysis.warnings.length}
                </div>
                <div className="text-sm text-gray-600 mt-1">Issues Found</div>
              </div>
            </div>

            {/* Risk Details */}
            {credibilityResult.analysis.risks.length > 0 && (
              <div className="mb-6">
                <h4 className="font-semibold text-red-600 mb-3 flex items-center justify-center">
                  <AlertTriangle className="w-5 h-5 mr-2" />
                  High Risk Issues
                </h4>
                <ul className="bg-red-50 border border-red-200 rounded-lg p-4 space-y-2">
                  {credibilityResult.analysis.risks.map((risk, index) => (
                    <li key={index} className="text-sm text-red-700 flex items-start">
                      <span className="text-red-500 mr-2">•</span>
                      {risk}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Warnings */}
            {credibilityResult.analysis.warnings.length > 0 && (
              <div className="mb-6">
                <h4 className="font-semibold text-yellow-600 mb-3 flex items-center justify-center">
                  <AlertTriangle className="w-5 h-5 mr-2" />
                  Warnings
                </h4>
                <ul className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 space-y-2">
                  {credibilityResult.analysis.warnings.map((warning, index) => (
                    <li key={index} className="text-sm text-yellow-700 flex items-start">
                      <span className="text-yellow-500 mr-2">•</span>
                      {warning}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* App Details */}
            <div className="bg-gray-50 p-4 rounded-lg">
              <h4 className="font-medium mb-4 text-center">App Details</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div className="space-y-2">
                  <p><strong>Package:</strong> {credibilityResult.appData.packageName}</p>
                  <p><strong>Version:</strong> {credibilityResult.appData.version}</p>
                  <p><strong>Developer:</strong> {credibilityResult.appData.developer}</p>
                  <p><strong>Size:</strong> {(credibilityResult.appData.size / 1024 / 1024).toFixed(2)} MB</p>
                </div>
                <div className="space-y-2">
                  <p><strong>Activities:</strong> {credibilityResult.appData.activities?.length || 0}</p>
                  <p><strong>Services:</strong> {credibilityResult.appData.services?.length || 0}</p>
                  <p><strong>Permissions:</strong> {credibilityResult.appData.permissions?.length || 0}</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <footer className="mt-12 py-6 bg-white border-t">
        <p className="text-center text-gray-600 text-sm">
          © 2025 Sentinels - Protecting you from clone and fake apps
        </p>
      </footer>
    </div>
  );
};

export default SentinelsScanner;