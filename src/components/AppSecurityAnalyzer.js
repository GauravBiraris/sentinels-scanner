import React, { useState } from 'react';
import JSZip from 'jszip';
import { DOMParser } from 'xmldom';

const AppSecurityAnalyzer = () => {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [error, setError] = useState(null);

  // Red flag patterns for security analysis
  const RED_FLAGS = {
    sensitivePermissions: [
      'SEND_SMS', 'RECEIVE_SMS', 'READ_SMS', 'WRITE_SMS',
      'CALL_PHONE', 'READ_PHONE_STATE', 'PROCESS_OUTGOING_CALLS',
      'WRITE_SETTINGS', 'WRITE_SECURE_SETTINGS', 'SYSTEM_ALERT_WINDOW',
      'DEVICE_POWER', 'REBOOT', 'MOUNT_UNMOUNT_FILESYSTEMS',
      'INSTALL_PACKAGES', 'DELETE_PACKAGES', 'CLEAR_APP_USER_DATA'
    ],
    socialAppAccess: [
      'whatsapp', 'telegram', 'instagram', 'facebook', 'youtube', 
      'snapchat', 'linkedin', 'twitter', 'tiktok'
    ],
    paymentKeywords: [
      'credit card', 'debit card', 'cvv', 'card number', 'expiry',
      'account number', 'routing number', 'bank account', 'payment',
      'billing', 'transaction'
    ],
    privacyKeywords: [
      'aadhar', 'aadhaar', 'passport', 'ssn', 'social security',
      'national id', 'identity card', 'license number'
    ],
    suspiciousUrls: [
      'http://', 'ftp://', '192.168.', '10.0.', '172.16.'
    ],
    passwordKeywords: [
      'password', 'pin', 'secret', 'key', 'token', 'credential'
    ]
  };

  const parseAPK = async (file) => {
    try {
      const zip = await JSZip.loadAsync(file);
      const manifestFile = zip.file('AndroidManifest.xml');
      
      if (!manifestFile) {
        throw new Error('AndroidManifest.xml not found');
      }

      const manifestContent = await manifestFile.async('uint8array');
      const manifestText = await extractAndroidManifest(manifestContent);
      
      // Parse resources and code files
      const resources = await parseResources(zip);
      const codeAnalysis = await analyzeCode(zip);
      
      return {
        type: 'APK',
        manifest: parseManifest(manifestText),
        resources,
        codeAnalysis,
        size: file.size
      };
    } catch (error) {
      throw new Error(`APK parsing failed: ${error.message}`);
    }
  };

  const parseIPA = async (file) => {
    try {
      const zip = await JSZip.loadAsync(file);
      let plistContent = null;
      let appFolder = null;

      // Find the app folder and Info.plist
      await zip.forEach((relativePath, zipEntry) => {
        if (relativePath.includes('.app/Info.plist')) {
          plistContent = zipEntry;
          appFolder = relativePath.split('/')[1];
        }
      });

      if (!plistContent) {
        throw new Error('Info.plist not found');
      }

      const plistText = await plistContent.async('text');
      const resources = await parseIOSResources(zip, appFolder);
      const codeAnalysis = await analyzeIOSCode(zip);

      return {
        type: 'IPA',
        plist: parsePlist(plistText),
        resources,
        codeAnalysis,
        size: file.size
      };
    } catch (error) {
      throw new Error(`IPA parsing failed: ${error.message}`);
    }
  };

  const extractAndroidManifest = async (manifestData) => {
    // Simplified Android manifest parsing (binary XML to text)
    // In production, use proper AXML parser
    try {
      const decoder = new TextDecoder('utf-8');
      return decoder.decode(manifestData);
    } catch {
      // Fallback for binary XML
      return '<manifest><!-- Binary XML - requires specialized parser --></manifest>';
    }
  };

  const parseManifest = (manifestText) => {
    const parser = new DOMParser();
    const doc = parser.parseFromString(manifestText, 'text/xml');
    
    const permissions = [];
    const activities = [];
    const services = [];
    const receivers = [];

    // Extract permissions
    const permNodes = doc.getElementsByTagName('uses-permission');
    for (let i = 0; i < permNodes.length; i++) {
      const name = permNodes[i].getAttribute('android:name');
      if (name) permissions.push(name.replace('android.permission.', ''));
    }

    // Extract components
    const activityNodes = doc.getElementsByTagName('activity');
    for (let i = 0; i < activityNodes.length; i++) {
      const name = activityNodes[i].getAttribute('android:name');
      if (name) activities.push(name);
    }

    const serviceNodes = doc.getElementsByTagName('service');
    for (let i = 0; i < serviceNodes.length; i++) {
      const name = serviceNodes[i].getAttribute('android:name');
      if (name) services.push(name);
    }

    const receiverNodes = doc.getElementsByTagName('receiver');
    for (let i = 0; i < receiverNodes.length; i++) {
      const name = receiverNodes[i].getAttribute('android:name');
      if (name) receivers.push(name);
    }

    return { permissions, activities, services, receivers };
  };

  const parsePlist = (plistText) => {
    // Basic plist parsing for iOS
    const bundleIdMatch = plistText.match(/<key>CFBundleIdentifier<\/key>\s*<string>([^<]+)<\/string>/);
    const appNameMatch = plistText.match(/<key>CFBundleDisplayName<\/key>\s*<string>([^<]+)<\/string>/);
    const versionMatch = plistText.match(/<key>CFBundleShortVersionString<\/key>\s*<string>([^<]+)<\/string>/);
    
    return {
      bundleId: bundleIdMatch ? bundleIdMatch[1] : 'Unknown',
      appName: appNameMatch ? appNameMatch[1] : 'Unknown',
      version: versionMatch ? versionMatch[1] : 'Unknown'
    };
  };

  const parseResources = async (zip) => {
    const strings = [];
    const layouts = [];
    
    await zip.forEach(async (relativePath, zipEntry) => {
      if (relativePath.includes('res/values/strings.xml')) {
        try {
          const content = await zipEntry.async('text');
          strings.push(...extractStrings(content));
        } catch (e) {
          console.warn('Failed to parse strings.xml');
        }
      }
      if (relativePath.includes('res/layout/') && relativePath.endsWith('.xml')) {
        try {
          const content = await zipEntry.async('text');
          layouts.push(extractLayoutInfo(content));
        } catch (e) {
          console.warn('Failed to parse layout file');
        }
      }
    });

    return { strings, layouts };
  };

  const parseIOSResources = async (zip, appFolder) => {
    const strings = [];
    
    await zip.forEach(async (relativePath, zipEntry) => {
      if (relativePath.includes('.lproj/') && relativePath.endsWith('.strings')) {
        try {
          const content = await zipEntry.async('text');
          strings.push(...extractIOSStrings(content));
        } catch (e) {
          console.warn('Failed to parse iOS strings file');
        }
      }
    });

    return { strings };
  };

  const analyzeCode = async (zip) => {
    const codeFiles = [];
    const networkCalls = [];
    
    await zip.forEach(async (relativePath, zipEntry) => {
      if (relativePath.endsWith('.dex') || relativePath.endsWith('.so')) {
        codeFiles.push(relativePath);
      }
      
      // Look for network configuration
      if (relativePath.includes('network_security_config.xml')) {
        try {
          const content = await zipEntry.async('text');
          networkCalls.push(...analyzeNetworkConfig(content));
        } catch (e) {
          console.warn('Failed to analyze network config');
        }
      }
    });

    return { codeFiles, networkCalls };
  };

  const analyzeIOSCode = async (zip) => {
    const codeFiles = [];
    
    await zip.forEach((relativePath, zipEntry) => {
      if (relativePath.endsWith('.dylib') || relativePath.includes('.framework/')) {
        codeFiles.push(relativePath);
      }
    });

    return { codeFiles };
  };

  const extractStrings = (xmlContent) => {
    const strings = [];
    const matches = xmlContent.match(/<string[^>]*>([^<]+)<\/string>/g);
    if (matches) {
      matches.forEach(match => {
        const content = match.replace(/<[^>]*>/g, '');
        strings.push(content);
      });
    }
    return strings;
  };

  const extractIOSStrings = (content) => {
    const strings = [];
    const lines = content.split('\n');
    lines.forEach(line => {
      const match = line.match(/"([^"]+)"/g);
      if (match) {
        strings.push(...match.map(s => s.replace(/"/g, '')));
      }
    });
    return strings;
  };

  const extractLayoutInfo = (xmlContent) => {
    const inputs = [];
    const editTextMatches = xmlContent.match(/<EditText[^>]*>/g) || [];
    const inputMatches = xmlContent.match(/android:inputType="([^"]+)"/g) || [];
    const hintMatches = xmlContent.match(/android:hint="([^"]+)"/g) || [];
    
    return {
      editTexts: editTextMatches.length,
      inputTypes: inputMatches.map(m => m.replace(/android:inputType="([^"]+)"/, '$1')),
      hints: hintMatches.map(m => m.replace(/android:hint="([^"]+)"/, '$1'))
    };
  };

  const analyzeNetworkConfig = (configContent) => {
    const calls = [];
    if (configContent.includes('cleartextTrafficPermitted="true"')) {
      calls.push('Cleartext HTTP traffic allowed');
    }
    return calls;
  };

  const performSecurityAnalysis = (appData) => {
    const flags = [];
    const score = { total: 0, max: 0 };

    // Check permissions
    if (appData.manifest?.permissions) {
      const sensitivePerms = appData.manifest.permissions.filter(perm =>
        RED_FLAGS.sensitivePermissions.some(flag => perm.includes(flag))
      );
      if (sensitivePerms.length > 0) {
        flags.push({
          type: 'HIGH',
          category: 'Permissions',
          message: `Suspicious permissions detected: ${sensitivePerms.join(', ')}`,
          details: sensitivePerms
        });
        score.total += sensitivePerms.length * 3;
      }
      score.max += 15;
    }

    // Check for payment-related content
    const allStrings = [
      ...(appData.resources?.strings || []),
      ...(appData.resources?.layouts?.flatMap(l => l.hints) || [])
    ].join(' ').toLowerCase();

    const paymentFlags = RED_FLAGS.paymentKeywords.filter(keyword =>
      allStrings.includes(keyword)
    );
    if (paymentFlags.length > 0) {
      flags.push({
        type: 'HIGH',
        category: 'Payment Data',
        message: `Requests sensitive payment information: ${paymentFlags.join(', ')}`,
        details: paymentFlags
      });
      score.total += paymentFlags.length * 4;
    }
    score.max += 20;

    // Check for privacy violations
    const privacyFlags = RED_FLAGS.privacyKeywords.filter(keyword =>
      allStrings.includes(keyword)
    );
    if (privacyFlags.length > 0) {
      flags.push({
        type: 'MEDIUM',
        category: 'Privacy',
        message: `Requests sensitive personal data: ${privacyFlags.join(', ')}`,
        details: privacyFlags
      });
      score.total += privacyFlags.length * 2;
    }
    score.max += 10;

    // Check for social app access
    const socialFlags = RED_FLAGS.socialAppAccess.filter(app =>
      allStrings.includes(app) || 
      appData.manifest?.permissions?.some(perm => perm.toLowerCase().includes(app))
    );
    if (socialFlags.length > 0) {
      flags.push({
        type: 'HIGH',
        category: 'Social Media Access',
        message: `Attempts to access social media apps: ${socialFlags.join(', ')}`,
        details: socialFlags
      });
      score.total += socialFlags.length * 3;
    }
    score.max += 15;

    // Check for insecure network connections
    const networkIssues = appData.codeAnalysis?.networkCalls?.filter(call =>
      call.includes('HTTP') || call.includes('cleartext')
    ) || [];
    if (networkIssues.length > 0) {
      flags.push({
        type: 'MEDIUM',
        category: 'Network Security',
        message: 'Uses insecure network connections',
        details: networkIssues
      });
      score.total += networkIssues.length * 2;
    }
    score.max += 10;

    // Calculate risk score
    const riskScore = score.max > 0 ? Math.round((score.total / score.max) * 100) : 0;
    
    let riskLevel = 'LOW';
    if (riskScore > 70) riskLevel = 'CRITICAL';
    else if (riskScore > 50) riskLevel = 'HIGH';
    else if (riskScore > 30) riskLevel = 'MEDIUM';

    return {
      flags,
      riskScore,
      riskLevel,
      summary: {
        totalFlags: flags.length,
        highRiskFlags: flags.filter(f => f.type === 'HIGH').length,
        mediumRiskFlags: flags.filter(f => f.type === 'MEDIUM').length
      }
    };
  };

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
      setAnalysis(null);
    }
  };

  const analyzeApp = async () => {
    if (!file) {
      setError('Please select a file');
      return;
    }

    setLoading(true);
    setError(null);
    setAnalysis(null);

    try {
      let appData;
      
      if (file.name.toLowerCase().endsWith('.apk')) {
        appData = await parseAPK(file);
      } else {
        appData = await parseIPA(file);
      }

      const securityAnalysis = performSecurityAnalysis(appData);

      setAnalysis({
        ...appData,
        security: securityAnalysis
      });

    } catch (err) {
      setError(`Analysis failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (level) => {
    switch (level) {
      case 'CRITICAL': return 'text-red-800 bg-red-100';
      case 'HIGH': return 'text-red-700 bg-red-50';
      case 'MEDIUM': return 'text-yellow-700 bg-yellow-50';
      default: return 'text-green-700 bg-green-50';
    }
  };

  const getFlagColor = (type) => {
    switch (type) {
      case 'HIGH': return 'border-red-500 bg-red-50';
      case 'MEDIUM': return 'border-yellow-500 bg-yellow-50';
      default: return 'border-blue-500 bg-blue-50';
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-6">
      <h2 className="text-2xl font-bold mb-6 text-gray-800">App Security Analyzer</h2>
      
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-2 text-gray-700">
            Select App File (APK/IPA)
          </label>
          <input
            type="file"
            accept=".apk,.ipa"
            onChange={handleFileChange}
            className="w-full p-3 border-2 border-gray-300 rounded-lg focus:border-blue-500"
          />
        </div>

        <button
          onClick={analyzeApp}
          disabled={loading || !file}
          className="w-full py-4 px-6 text-white font-medium rounded-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center transition-colors"
          style={{ backgroundColor: '#CD853F' }}
        >
          {loading ? 'Analyzing...' : 'Analyze App Security'}
        </button>
      </div>

      {error && (
        <div className="mt-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded-lg">
          {error}
        </div>
      )}

      {analysis && (
        <div className="mt-6 space-y-6">
          {/* Risk Overview */}
          <div className={`p-4 rounded-lg border-2 ${getRiskColor(analysis.security.riskLevel)}`}>
            <h3 className="text-xl font-bold mb-2">Security Risk: {analysis.security.riskLevel}</h3>
            <p className="text-lg">Risk Score: {analysis.security.riskScore}/100</p>
            <p className="text-sm mt-2">
              {analysis.security.summary.totalFlags} security issues found 
              ({analysis.security.summary.highRiskFlags} high risk, {analysis.security.summary.mediumRiskFlags} medium risk)
            </p>
          </div>

          {/* Security Flags */}
          {analysis.security.flags.length > 0 && (
            <div>
              <h3 className="text-lg font-semibold mb-3">Security Issues</h3>
              <div className="space-y-3">
                {analysis.security.flags.map((flag, index) => (
                  <div key={index} className={`p-3 border-l-4 rounded ${getFlagColor(flag.type)}`}>
                    <div className="flex items-center justify-between">
                      <span className="font-medium">{flag.category}</span>
                      <span className={`px-2 py-1 text-xs rounded ${flag.type === 'HIGH' ? 'bg-red-200 text-red-800' : 'bg-yellow-200 text-yellow-800'}`}>
                        {flag.type} RISK
                      </span>
                    </div>
                    <p className="text-sm mt-1">{flag.message}</p>
                    {flag.details && (
                      <details className="mt-2">
                        <summary className="text-xs cursor-pointer">View Details</summary>
                        <pre className="text-xs mt-1 p-2 bg-gray-100 rounded overflow-auto">
                          {JSON.stringify(flag.details, null, 2)}
                        </pre>
                      </details>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* App Details */}
          <div className="bg-gray-50 p-4 rounded-lg">
            <h3 className="text-lg font-semibold mb-3">App Information</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <p><strong>Type:</strong> {analysis.type}</p>
                <p><strong>Size:</strong> {(analysis.size / 1024 / 1024).toFixed(2)} MB</p>
                {analysis.manifest && (
                  <>
                    <p><strong>Permissions:</strong> {analysis.manifest.permissions?.length || 0}</p>
                    <p><strong>Activities:</strong> {analysis.manifest.activities?.length || 0}</p>
                  </>
                )}
                {analysis.plist && (
                  <>
                    <p><strong>Bundle ID:</strong> {analysis.plist.bundleId}</p>
                    <p><strong>App Name:</strong> {analysis.plist.appName}</p>
                    <p><strong>Version:</strong> {analysis.plist.version}</p>
                  </>
                )}
              </div>
              <div>
                <p><strong>Code Files:</strong> {analysis.codeAnalysis?.codeFiles?.length || 0}</p>
                <p><strong>String Resources:</strong> {analysis.resources?.strings?.length || 0}</p>
                {analysis.resources?.layouts && (
                  <p><strong>Layout Files:</strong> {analysis.resources.layouts.length}</p>
                )}
              </div>
            </div>
          </div>

          {/* Detailed Analysis */}
          <details className="bg-gray-50 p-4 rounded-lg">
            <summary className="font-semibold cursor-pointer">View Full Analysis Report</summary>
            <pre className="mt-3 text-xs overflow-auto bg-white p-3 rounded border">
              {JSON.stringify(analysis, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </div>
  );
};

export default AppSecurityAnalyzer;