# GitHub Setup Instructions

## Step 1: Create GitHub Repository

1. Go to https://github.com/new
2. Enter repository name: `execution-aware-scanner`
3. Set description: "Production-ready eBPF security scanner with execution-aware vulnerability detection"
4. Choose visibility: Public or Private
5. Do NOT initialize with README (we already have one)
6. Click "Create repository"

## Step 2: Push to GitHub

Run these commands on your Linux machine:

```bash
# Clone the repository (from wherever you saved it)
cd /path/to/execution-aware-scanner

# Add GitHub remote
# For HTTPS:
git remote add origin https://github.com/YOUR_USERNAME/execution-aware-scanner.git

# For SSH (recommended):
git remote add origin git@github.com:YOUR_USERNAME/execution-aware-scanner.git

# Push to GitHub
git branch -M main
git push -u origin main
```

## Step 3: Verify

Check that everything uploaded correctly:

```bash
# View remote URL
git remote -v

# Check status
git status

# View log
git log --oneline
```

## Step 4: Clone on Linux

Now you can clone it on any Linux machine:

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/execution-aware-scanner.git

# Or with SSH
git clone git@github.com:YOUR_USERNAME/execution-aware-scanner.git

# Enter directory
cd execution-aware-scanner

# Verify files
ls -la
```

## Step 5: Build on Linux

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install eBPF toolchain
rustup target add bpfel-unknown-none
cargo install bpf-linker

# Build the project
cargo build --release

# Run tests
cargo test --workspace

# Run the scanner
sudo ./target/release/scanner-agent
```

## Alternative: Download as ZIP

If you prefer not to use git:

1. Go to: https://github.com/YOUR_USERNAME/execution-aware-scanner
2. Click "Code" button
3. Select "Download ZIP"
4. Extract on Linux: `unzip execution-aware-scanner-main.zip`
5. Rename: `mv execution-aware-scanner-main execution-aware-scanner`

## Repository Structure

```
execution-aware-scanner/
├── Cargo.toml                  # Workspace root
├── README.md                   # Main documentation
├── Dockerfile                  # Container image
├── deploy/                     # Kubernetes manifests
├── helm/                       # Helm charts
├── docs/                       # Documentation
│   ├── DEPLOYMENT_GUIDE.md
│   ├── PRODUCTION.md
│   └── OPERATIONS.md
├── scanner-common/             # Shared types
├── scanner-ebpf/               # Kernel eBPF programs
├── scanner-agent/              # User-space daemon
├── tests/                      # Integration tests
└── .github/workflows/          # CI/CD
```

## Next Steps

1. **Set up GitHub Actions**: The CI/CD pipeline is already in `.github/workflows/ci.yaml`
2. **Create releases**: Tag versions and create releases
3. **Enable discussions**: For community support
4. **Add branch protection**: For pull requests

## Quick Commands Reference

```bash
# Check repository status
git status

# View commit history
git log --oneline

# Pull latest changes
git pull origin main

# Push changes
git push origin main

# Create a branch
git checkout -b feature/my-feature

# Switch branches
git checkout main

# View differences
git diff

# Stash changes
git stash

# Apply stashed changes
git stash pop
```

## Troubleshooting

### Authentication Issues

```bash
# Configure git credentials
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# For HTTPS, use token instead of password
# Generate token at: https://github.com/settings/tokens
# Use token as password when prompted

# For SSH, add key
cat ~/.ssh/id_rsa.pub
# Copy output to: https://github.com/settings/keys
```

### Large File Issues

If files are too large:

```bash
# Use Git LFS for large files
git lfs track "*.o"
git lfs track "*.elf"
git add .gitattributes
```

---

**Your repository is ready to use on Linux!**
