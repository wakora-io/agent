set -e
cd /mnt/d/Projects/Costlyzer/agent
git add -A
git status --short
git commit -F .git-msg-tmp -q
rm -f .git-msg-tmp
git log -1 --oneline
git push -q origin main
echo PUSHED_MAIN
git tag r296
git push -q origin r296
echo PUSHED_TAG_r296
