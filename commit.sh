git checkout main
git add .
git commit -m "Auto Update $(date '+%Y-%m-%d %H:%M:%S')" || echo "Nothing to commit"
git push origin main --force
