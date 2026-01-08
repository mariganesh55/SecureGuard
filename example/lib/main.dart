import 'package:flutter/material.dart';

/// Production Banking App Example
/// 
/// For production banking apps, you don't need Flutter UI for security.
/// Native SecureGuard automatically protects the app:
/// - Terminates if rooted/emulator/debugger/dev mode detected
/// - No UI needed - app just won't start on insecure devices
/// 
/// This is a minimal example showing app runs normally on secure devices.

void main() {
  runApp(const BankingApp());
}

class BankingApp extends StatelessWidget {
  const BankingApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Secure Banking App',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatelessWidget {
  const HomePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: const Text('Secure Banking App'),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Icon(
              Icons.security,
              size: 100,
              color: Colors.green,
            ),
            const SizedBox(height: 20),
            const Text(
              '✅ Device is Secure',
              style: TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
                color: Colors.green,
              ),
            ),
            const SizedBox(height: 10),
            Text(
              'SecureGuard verified this device',
              style: TextStyle(
                fontSize: 16,
                color: Colors.grey[600],
              ),
            ),
            const SizedBox(height: 40),
            const Padding(
              padding: EdgeInsets.all(20.0),
              child: Text(
                'If this screen appears, your device passed all security checks:\n\n'
                '✓ Not rooted\n'
                '✓ Not an emulator\n'
                '✓ Developer mode disabled\n'
                '✓ No debugger attached\n'
                '✓ No hooking frameworks detected',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 14),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
