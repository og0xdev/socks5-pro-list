while true
do
   git checkout main
   git add .

   git diff --cached --quiet || \
   git commit -m "Auto Update $(date '+%Y-%m-%d %H:%M:%S')" || echo "Nothing to commit"
   
   git push origin main --force

   sleep $((300 + RANDOM % 300))
done
