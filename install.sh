#!/bin/bash
echo "🔧 Installing FTP Brute Force Tool..."

# Check Python version
python3 --version > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "❌ Python3 is not installed. Please install Python3 first."
    exit 1
fi

echo "📦 Installing dependencies..."
pip3 install -r requirements.txt

# Make script executable
chmod +x ftpbrute.py

echo "✅ Installation complete!"
echo ""
echo "Usage examples:"
echo "  ./ftpbrute.py -t 192.168.1.100 -U users.txt -P passwords.txt"
echo "  ./ftpbrute.py -t ftp.target.com --ftps -U users.txt -P pass.txt"
echo ""
echo "For help: ./ftpbrute.py --help"
