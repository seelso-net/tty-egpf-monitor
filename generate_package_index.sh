#!/bin/bash

# Generate static index.html files for package directories

generate_package_index() {
    local dir="$1"
    local title="$2"
    local note="$3"
    
    cat > "${dir}/index.html" << HTML
<!DOCTYPE html>
<html>
<head>
    <title>${title} - Package Files</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 900px; margin: 0 auto; }
        h1 { color: #2563eb; }
        .package-list { font-family: monospace; font-size: 0.9em; line-height: 1.6; }
        .package-list a { color: #2563eb; text-decoration: none; display: block; padding: 0.2em 0; }
        .package-list a:hover { text-decoration: underline; background: #f0f9ff; }
        a { color: #2563eb; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .info { background: #f0f9ff; padding: 1rem; border-radius: 0.5rem; margin: 1rem 0; }
        .stats { background: #f8f9fa; padding: 0.5rem; border-radius: 0.25rem; margin: 1rem 0; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>${title} - Package Files</h1>
        
        <div class="info">
            <p>${note}</p>
        </div>
        
        <div class="stats">
            <p><strong>Total packages:</strong> $(ls ${dir}/*.deb 2>/dev/null | wc -l)</p>
            <p><strong>Last updated:</strong> $(date)</p>
        </div>
        
        <h2>Available Packages</h2>
        <p>Click on any .deb file to download:</p>
        
        <div class="package-list">
            <ul>
HTML

    # List all .deb files in the directory
    for deb in "${dir}"/*.deb; do
        if [[ -f "$deb" ]]; then
            filename=$(basename "$deb")
            echo "                <li><a href=\"${filename}\">${filename}</a></li>" >> "${dir}/index.html"
        fi
    done

    cat >> "${dir}/index.html" << HTML
            </ul>
        </div>
        
        <p><a href="../">← Back to package pool</a> | <a href="../../">← Back to main repository</a></p>
    </div>
</body>
</html>
HTML
}

# Generate index files for both package directories
generate_package_index "pool/jammy" "Ubuntu 22.04 (Jammy)" "These packages include automatic libbpf compatibility handling for Ubuntu 22.04. The postinst script will build and install a newer libbpf if needed."

generate_package_index "pool/noble" "Ubuntu 24.04 (Noble)" "These packages use the native libbpf 1.7.0+ available in Ubuntu 24.04. No special libbpf handling is required."

echo "Generated package index files"
