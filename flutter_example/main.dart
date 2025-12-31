import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:async';

void main() {
  runApp(const SecureGuardDemoApp());
}

class SecureGuardDemoApp extends StatelessWidget {
  const SecureGuardDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SecureGuard Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        useMaterial3: true,
      ),
      home: const SecurityStatusPage(),
    );
  }
}

class SecurityStatusPage extends StatefulWidget {
  const SecurityStatusPage({super.key});

  @override
  State<SecurityStatusPage> createState() => _SecurityStatusPageState();
}

class _SecurityStatusPageState extends State<SecurityStatusPage> {
  static const platform = MethodChannel('com.secureguard.example/security');
  static const eventChannel = EventChannel('com.secureguard.example/security_events');
  
  bool _isSecure = true;
  List<Map<String, dynamic>> _threats = [];
  String _securityMode = "CHECKING...";
  int? _countdownSeconds;
  Timer? _countdownTimer;
  StreamSubscription? _eventSubscription;
  
  @override
  void initState() {
    super.initState();
    _initPlatformState();
    _listenToSecurityEvents();
  }
  
  @override
  void dispose() {
    _eventSubscription?.cancel();
    _countdownTimer?.cancel();
    super.dispose();
  }
  
  Future<void> _initPlatformState() async {
    try {
      final result = await platform.invokeMethod('getSecurityStatus');
      setState(() {
        _securityMode = result['mode'] ?? 'UNKNOWN';
      });
    } on PlatformException catch (e) {
      print("Failed to get security status: ${e.message}");
    }
  }
  
  void _listenToSecurityEvents() {
    _eventSubscription = eventChannel.receiveBroadcastStream().listen((event) {
      print("📥 Received security event: $event");
      
      if (event['type'] == 'threat') {
        _handleThreat(event);
      } else if (event['type'] == 'status') {
        _handleStatus(event);
      }
    }, onError: (error) {
      print("❌ Error receiving security events: $error");
    });
  }
  
  void _handleThreat(Map<dynamic, dynamic> event) {
    setState(() {
      _isSecure = false;
      _threats.add({
        'type': event['threatType'],
        'description': event['description'],
        'timestamp': event['timestamp'],
      });
    });
    
    // Check if this is a critical threat
    final threatType = event['threatType'];
    if (threatType == 'ROOT_DETECTED' || 
        threatType == 'EMULATOR_DETECTED' || 
        threatType == 'DEBUGGER_DETECTED') {
      _startCountdown();
    }
  }
  
  void _handleStatus(Map<dynamic, dynamic> event) {
    setState(() {
      _isSecure = event['passed'] == true;
      if (!_isSecure && event['threats'] != null) {
        // Add detected threats
        for (var threat in event['threats']) {
          if (!_threats.any((t) => t['type'] == threat)) {
            _threats.add({
              'type': threat,
              'description': _getThreatDescription(threat),
              'timestamp': event['timestamp'],
            });
          }
        }
      }
    });
  }
  
  void _startCountdown() {
    _countdownSeconds = 3;
    _countdownTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      setState(() {
        if (_countdownSeconds != null && _countdownSeconds! > 0) {
          _countdownSeconds = _countdownSeconds! - 1;
        } else {
          timer.cancel();
        }
      });
    });
  }
  
  String _getThreatDescription(String threatType) {
    switch (threatType) {
      case 'ROOT_DETECTED':
        return 'Device is rooted';
      case 'EMULATOR_DETECTED':
        return 'Running on emulator';
      case 'DEBUGGER_DETECTED':
        return 'Debugger attached';
      case 'FRIDA_DETECTED':
        return 'Frida framework detected';
      case 'XPOSED_DETECTED':
        return 'Xposed framework detected';
      case 'HOOKING_DETECTED':
        return 'Hooking attempt detected';
      default:
        return 'Security threat detected';
    }
  }
  
  IconData _getThreatIcon(String threatType) {
    switch (threatType) {
      case 'ROOT_DETECTED':
        return Icons.security;
      case 'EMULATOR_DETECTED':
        return Icons.phone_android;
      case 'DEBUGGER_DETECTED':
        return Icons.bug_report;
      case 'FRIDA_DETECTED':
      case 'XPOSED_DETECTED':
      case 'HOOKING_DETECTED':
        return Icons.warning;
      default:
        return Icons.error;
    }
  }
  
  Color _getThreatColor(String threatType) {
    switch (threatType) {
      case 'ROOT_DETECTED':
      case 'EMULATOR_DETECTED':
      case 'DEBUGGER_DETECTED':
        return Colors.red;
      case 'FRIDA_DETECTED':
      case 'XPOSED_DETECTED':
      case 'HOOKING_DETECTED':
        return Colors.orange;
      default:
        return Colors.red;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('🛡️ SecureGuard Demo'),
        backgroundColor: _isSecure ? Colors.green : Colors.red,
      ),
      body: Container(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: _isSecure 
              ? [Colors.green.shade50, Colors.white]
              : [Colors.red.shade50, Colors.white],
          ),
        ),
        child: SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(20.0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Status Card
                Card(
                  elevation: 4,
                  child: Padding(
                    padding: const EdgeInsets.all(20.0),
                    child: Column(
                      children: [
                        Icon(
                          _isSecure ? Icons.shield : Icons.warning,
                          size: 80,
                          color: _isSecure ? Colors.green : Colors.red,
                        ),
                        const SizedBox(height: 16),
                        Text(
                          _isSecure ? 'Device Secure' : 'Threats Detected!',
                          style: TextStyle(
                            fontSize: 24,
                            fontWeight: FontWeight.bold,
                            color: _isSecure ? Colors.green : Colors.red,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Mode: $_securityMode',
                          style: TextStyle(
                            fontSize: 14,
                            color: Colors.grey[600],
                          ),
                        ),
                        if (_countdownSeconds != null && _countdownSeconds! > 0) ...[
                          const SizedBox(height: 16),
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 16,
                              vertical: 8,
                            ),
                            decoration: BoxDecoration(
                              color: Colors.red.shade100,
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Text(
                              'App closing in $_countdownSeconds seconds...',
                              style: const TextStyle(
                                fontSize: 16,
                                fontWeight: FontWeight.bold,
                                color: Colors.red,
                              ),
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 24),
                
                // Threats Section
                if (_threats.isNotEmpty) ...[
                  const Text(
                    'Detected Threats:',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Expanded(
                    child: ListView.builder(
                      itemCount: _threats.length,
                      itemBuilder: (context, index) {
                        final threat = _threats[index];
                        return Card(
                          margin: const EdgeInsets.only(bottom: 12),
                          color: _getThreatColor(threat['type']).shade50,
                          child: ListTile(
                            leading: Icon(
                              _getThreatIcon(threat['type']),
                              color: _getThreatColor(threat['type']),
                              size: 32,
                            ),
                            title: Text(
                              threat['type'],
                              style: TextStyle(
                                fontWeight: FontWeight.bold,
                                color: _getThreatColor(threat['type']),
                              ),
                            ),
                            subtitle: Text(threat['description']),
                          ),
                        );
                      },
                    ),
                  ),
                ] else ...[
                  const Text(
                    'Security Checks:',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 12),
                  _buildCheckItem('Root Detection', true),
                  _buildCheckItem('Emulator Detection', true),
                  _buildCheckItem('Debugger Detection', true),
                  _buildCheckItem('Hooking Detection', true),
                  const Spacer(),
                  Center(
                    child: Text(
                      '✨ All security checks passed!',
                      style: TextStyle(
                        fontSize: 16,
                        color: Colors.green.shade700,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
  
  Widget _buildCheckItem(String label, bool passed) {
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: Icon(
          passed ? Icons.check_circle : Icons.cancel,
          color: passed ? Colors.green : Colors.red,
        ),
        title: Text(label),
        trailing: Text(
          passed ? 'Passed' : 'Failed',
          style: TextStyle(
            color: passed ? Colors.green : Colors.red,
            fontWeight: FontWeight.bold,
          ),
        ),
      ),
    );
  }
}
