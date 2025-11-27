#!/bin/bash

# Function to prompt for user confirmation (y/n)
function proceed_with_new_version {
    while true; do
        read -p "$* [y/n]: " yn
        case $yn in
            [Yy]*) return 0 ;;
            [Nn]*) echo "Aborted"; return 1 ;;
            *) echo "Invalid input $yn. Please enter y or n." ;;  # Handle invalid input
        esac
    done
}

# Ensure the huldra package is installed
if ! uv pip show huldra > /dev/null 2>&1; then
    echo "The 'huldra' package is not installed. Ensure you have activated the correct environment and installed all requirements."
    echo "You can install it with: uv pip install -e ."
    exit 1
fi

# Ensure GitHub CLI is installed and authenticated
if ! command -v gh &> /dev/null; then
    echo "GitHub CLI (gh) is not installed. Please install it to automate PR creation."
    exit 1
fi

if ! gh auth status &> /dev/null; then
    echo "You are not logged into GitHub CLI. Please run 'gh auth login'."
    exit 1
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "You have uncommitted changes in your working directory. Please commit or stash them before proceeding."
    exit 1
fi

# Ensure we're on the 'develop' branch and pull the latest changes
if ! git checkout develop; then
    echo "Failed to checkout the 'develop' branch. Ensure there are no conflicting changes and try again."
    exit 1
fi

git pull --tags

# Get the previous version from setuptools_scm
PREV_VERSION=$(python3 -m setuptools_scm | tail -n 1)
echo "Current version is $PREV_VERSION"

# Generate the changelog and bump version
make changelog

# Extract the new version from CHANGELOG.md
RELEASE_VERSION=$(awk '/<!-- insertion marker -->/{flag=1; next} flag && /^## \[/{gsub(/[\[\]]/, "", $2); split($2, a, "("); print a[1]; exit}' CHANGELOG.md)

if [ -z "$RELEASE_VERSION" ]; then
    echo "Failed to detect a new version in CHANGELOG.md after running 'make changelog'."
    echo "This might mean there are no new commits to be released."
    exit 1
fi

# Prompt user to accept or override the detected version
echo "Detected new version: $RELEASE_VERSION"
read -p "Press Enter to accept, or input a new version: " USER_VERSION
if [ -n "$USER_VERSION" ]; then
    # The version in the text header
    text_version_to_replace=$RELEASE_VERSION

    # The version in the URLs
    url_version_to_replace=$(awk -F'[/)]' '/<!-- insertion marker -->/{f=1;next} f && /## \[/ && /tags\//{print $(NF-1); exit}' CHANGELOG.md)

    if [ -z "$url_version_to_replace" ]; then
        url_version_to_replace=$text_version_to_replace
    fi

    # Escape dots for regex in awk
    old_text_v_esc=${text_version_to_replace//./\\.}
    old_url_v_esc=${url_version_to_replace//./\\.}

    # Update version in header and compare links
    awk -v uv="$USER_VERSION" \
        -v old_text_v="$old_text_v_esc" \
        -v old_url_v="$old_url_v_esc" '
        BEGIN { p=0; h=0; c=0; }
        /<!-- insertion marker -->/ { p=1; print; next }
        p && !h && /^## \[/ {
            sub("\\[" old_text_v "\\]", "[" uv "]");
            sub("/" old_url_v "\\)", "/" uv ")");
            h=1;
        }
        p && !c && /<small>\[Compare with/ {
            sub("\\.\\.\\." old_url_v "\\)", "..." uv ")");
            c=1;
        }
        { print }
    ' CHANGELOG.md > CHANGELOG.md.tmp && mv CHANGELOG.md.tmp CHANGELOG.md

    RELEASE_VERSION="$USER_VERSION"
    echo "Version updated to $RELEASE_VERSION in CHANGELOG.md"
fi

# Ensure the new version is different from the previous version
echo "New version is $RELEASE_VERSION"
if [ "$RELEASE_VERSION" == "$PREV_VERSION" ]; then
    echo "The new version $RELEASE_VERSION is the same as the previous version $PREV_VERSION."
    exit 1
fi

# Ensure the new version is greater than the previous version
# We use sort -V for robust version comparison.
# It checks if PREV_VERSION is listed before RELEASE_VERSION when sorted.
# If RELEASE_VERSION is smaller than PREV_VERSION, it will be listed first.
lowest_version=$(printf '%s\n' "$PREV_VERSION" "$RELEASE_VERSION" | sort -V | head -n 1)
if [ "$lowest_version" != "$PREV_VERSION" ]; then
    echo "The new version $RELEASE_VERSION must be greater than the previous version $PREV_VERSION."
    exit 1
fi

# Extract the changelog for the new version
CHANGELOG=$(awk '/^## \[/{if (p) exit; p=1} p' CHANGELOG.md | sed '/^<!--/,/^-->/d')

echo "$CHANGELOG"

# Confirm the version is correct
if ! proceed_with_new_version "Previous version was $PREV_VERSION and new version is $RELEASE_VERSION. Is this accurate?"; then
    exit 1  # Exit the script if the user does not confirm
fi

# Create and push the release branch and tag
BRANCH_NAME="release-$RELEASE_VERSION"

if git rev-parse --verify "$BRANCH_NAME" >/dev/null 2>&1; then
    git checkout "$BRANCH_NAME"
else
    git checkout -b "$BRANCH_NAME"
fi

git add .

COMMIT_MESSAGE="
chore: Release $RELEASE_VERSION 🚀

$CHANGELOG
"

git commit -m "$COMMIT_MESSAGE"

git tag -a "$RELEASE_VERSION" -m "Release $RELEASE_VERSION"
git push --force --set-upstream origin release-"$RELEASE_VERSION" --tags

# Create Pull Request on GitHub
echo "Creating Pull Request on GitHub..."
gh pr create --title "Release $RELEASE_VERSION" \
             --body "$CHANGELOG" \
             --base develop \
             --head release-"$RELEASE_VERSION"
