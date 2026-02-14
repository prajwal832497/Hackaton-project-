"""
Flask Security Scanner API Backend - EXE/APK Only
Simplified version for executable and Android app analysis
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import tempfile
from werkzeug.utils import secure_filename

# Import analyzers
from analyzers.api_keys import APIKeyAnalyzer
from analyzers.network import NetworkAnalyzer
from analyzers.cloud_storage import CloudStorageAnalyzer
from analyzers.android import AndroidAnalyzer  
from analyzers.infrastructure import InfrastructureAnalyzer
from analyzers.crypto import CryptoAnalyzer
from analyzers.debug import DebugAnalyzer
from analyzers.static_files import StaticFileAnalyzer

# Import utilities
from utils.file_handler import FileHandler
from utils.report_generator import ReportGenerator

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend access

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'apk', 'exe', 'pdf', 'jar', 'dll', 'so', 'ipa', 'js', 'html', 'htm', 'css', 'json'}  # Expanded support

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'Security Scanner API - EXE/APK Only'}), 200


@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    """
    Scan uploaded EXE or APK file for security vulnerabilities
    """
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Only .exe, .apk, .js, .html, .css files are supported'}), 400
        
        # Save file temporarily
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        try:
            # Get file information
            file_info = FileHandler.get_file_info(file_path)
            file_info['filename'] = filename
            file_info['type'], file_info['type_description'] = FileHandler.detect_file_type(file_path)
            
            # Calculate file hash
            file_hash = FileHandler.calculate_hash(file_path)
            
            # Calculate entropy
            file_info['entropy'] = FileHandler.calculate_entropy(file_path)
            
            # Extract strings from file
            file_content = FileHandler.extract_strings(file_path)
            
            # Run all analyzers
            all_findings = {}
            
            # Standard Analyzers
            all_findings['api_keys'] = APIKeyAnalyzer().analyze(file_content, filename)
            all_findings['network'] = NetworkAnalyzer().analyze(file_content, filename)
            all_findings['cloud_storage'] = CloudStorageAnalyzer().analyze(file_content, filename)
            all_findings['infrastructure'] = InfrastructureAnalyzer().analyze(file_content, filename)
            all_findings['cryptography'] = CryptoAnalyzer().analyze(file_content, filename)
            all_findings['debug'] = DebugAnalyzer().analyze(file_content, filename)
            
            # Static File Analysis
            if filename.rsplit('.', 1)[1].lower() in ['js', 'html', 'htm', 'css', 'json']:
                all_findings['static_analysis'] = StaticFileAnalyzer().analyze(file_content, filename)

            # Android Specific (for APK files)
            if file_info['type'] in ['ZIP/APK', 'APK'] or filename.lower().endswith('.apk'):
                all_findings['android'] = AndroidAnalyzer().analyze_apk(file_path)
            
            # Generate report
            report = ReportGenerator.generate_report(all_findings, file_info, file_hash)
            
            return jsonify(report), 200
            
        finally:
            # Clean up temporary file
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


if __name__ == '__main__':
    print(" ")
    print("=" * 60)
    print("  Security Scanner API Server")
    print("=" * 60)
    print("  Supported Files: .exe, .apk")
    print("  Host: http://localhost:5000")
    print("=" * 60)
    print(" ")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
