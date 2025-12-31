#!/bin/bash

# 🚀 Quick Publish Script for SecureGuard
# This script helps you publish to JitPack in 5 minutes

echo "🔒 SecureGuard Publishing Assistant"
echo "===================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Check if Git is initialized
echo "📝 Step 1: Checking Git repository..."
if [ ! -d ".git" ]; then
    echo -e "${YELLOW}Git not initialized. Initializing...${NC}"
    git init
    echo -e "${GREEN}✅ Git initialized${NC}"
else
    echo -e "${GREEN}✅ Git repository found${NC}"
fi
echo ""

# Step 2: Check if GitHub username is configured
echo "📝 Step 2: GitHub Configuration"
echo "Enter your GitHub username:"
read github_username

if [ -z "$github_username" ]; then
    echo -e "${RED}❌ GitHub username required!${NC}"
    exit 1
fi

# Update build.gradle with username
echo "Updating build.gradle with your GitHub username..."
sed -i.bak "s/yourusername/$github_username/g" secureguard/build.gradle
rm secureguard/build.gradle.bak
echo -e "${GREEN}✅ build.gradle updated${NC}"
echo ""

# Step 3: Check version
echo "📝 Step 3: Version Configuration"
echo "Enter version number (default: 1.0.0):"
read version_number
version_number=${version_number:-1.0.0}
echo -e "${GREEN}✅ Version set to: $version_number${NC}"
echo ""

# Step 4: Build AAR
echo "📝 Step 4: Building AAR..."
./gradlew :secureguard:assembleRelease
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ AAR built successfully${NC}"
else
    echo -e "${RED}❌ AAR build failed!${NC}"
    exit 1
fi
echo ""

# Step 5: Git operations
echo "📝 Step 5: Git Commit & Tag"
echo "Do you want to commit and tag now? (y/n)"
read do_commit

if [ "$do_commit" = "y" ]; then
    # Add files
    git add .
    
    # Commit
    echo "Enter commit message (default: Release v$version_number):"
    read commit_msg
    commit_msg=${commit_msg:-"Release v$version_number"}
    git commit -m "$commit_msg"
    
    # Tag
    git tag "v$version_number"
    
    echo -e "${GREEN}✅ Committed and tagged${NC}"
    echo ""
    
    # Push
    echo "📝 Step 6: Push to GitHub"
    echo "GitHub repository URL (e.g., https://github.com/$github_username/SecureGuard.git):"
    read repo_url
    
    if [ -z "$repo_url" ]; then
        repo_url="https://github.com/$github_username/SecureGuard.git"
    fi
    
    # Check if remote exists
    if ! git remote | grep -q "origin"; then
        git remote add origin "$repo_url"
    fi
    
    echo "Pushing to GitHub..."
    git push -u origin main
    git push origin "v$version_number"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Pushed to GitHub${NC}"
    else
        echo -e "${YELLOW}⚠️  Push failed. You may need to create the repo first or check credentials${NC}"
    fi
fi
echo ""

# Step 7: JitPack instructions
echo "📝 Step 7: JitPack Publishing"
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}🎉 Almost Done!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "To complete publishing on JitPack:"
echo ""
echo "1. Create GitHub Release:"
echo "   - Go to: https://github.com/$github_username/SecureGuard/releases/new"
echo "   - Tag: v$version_number"
echo "   - Title: SecureGuard v$version_number"
echo "   - Click 'Publish release'"
echo ""
echo "2. Trigger JitPack Build:"
echo "   - Visit: https://jitpack.io/#$github_username/SecureGuard"
echo "   - Click 'Get it' on v$version_number"
echo ""
echo "3. Users can now add your library:"
echo ""
echo -e "${YELLOW}// Add JitPack repository${NC}"
echo "allprojects {"
echo "    repositories {"
echo "        maven { url 'https://jitpack.io' }"
echo "    }"
echo "}"
echo ""
echo -e "${YELLOW}// Add dependency${NC}"
echo "dependencies {"
echo "    implementation 'com.github.$github_username:SecureGuard:$version_number'"
echo "}"
echo ""
echo -e "${GREEN}========================================${NC}"
echo ""
echo "📚 Documentation:"
echo "   - Publishing Guide: PUBLISHING_GUIDE.md"
echo "   - Integration Guide: INTEGRATION_GUIDE.md"
echo ""
echo "🌟 Don't forget to:"
echo "   - Add README.md to GitHub"
echo "   - Add LICENSE file"
echo "   - Create GitHub Release"
echo ""
echo -e "${GREEN}✅ Setup Complete!${NC}"
