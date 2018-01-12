
## Time machine shuttle
`git  status` look the status the work area,
if the file has modified,`git diff`can view the changes.

```c
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# echo "hello" > readme 
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git status 
On branch master
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

	modified:   readme

no changes added to commit (use "git add" and/or "git commit -a")

```
`git status`tell us the file readme was modified but not yet ready to commit changes.

```c
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git diff
diff --git a/readme b/readme
index 347140a..ce01362 100644
--- a/readme
+++ b/readme
@@ -1 +1 @@
-git is a version control system
+hello
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit#

```
`git diff`tell us the diff 


```c
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git add readme 
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git commit -m "add hello"
[master 9d42218] add hello
 1 file changed, 1 insertion(+), 1 deletion(-)
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git status
On branch master
nothing to commit, working tree clean
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git diff
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# 
```

## Version rollback

`HEAD` point to current version
`git reset --hard commit_id`shuttle between versions of history
`git log`view the submission history to help which version to roll back
`git reflog` check the command history to help which version to return to the future

- roll back 

```c
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# cat readme 
hello
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# 
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git log 
commit 9d42218388e08b82f9135c39bb3e1cc1a07c6e91 (HEAD -> master)
Author: gutttt <393803933@qq.com>
Date:   Wed Jan 10 15:00:43 2018 +0800

    add hello

commit 964756fccfba8bccdc72d7515d2fd52a9c4f3c88
Author: gutttt <393803933@qq.com>
Date:   Wed Jan 10 14:38:06 2018 +0800

    write readme file
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git reset --hard HEAD~1
HEAD is now at 964756f write readme file
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# cat readme 
git is a version control system
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# 
```

- return to the future

```c
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git log 
commit 964756fccfba8bccdc72d7515d2fd52a9c4f3c88 (HEAD -> master)
Author: gutttt <393803933@qq.com>
Date:   Wed Jan 10 14:38:06 2018 +0800

    write readme file
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git reflog 
964756f (HEAD -> master) HEAD@{0}: reset: moving to HEAD~1
9d42218 HEAD@{1}: commit: add hello
964756f (HEAD -> master) HEAD@{2}: commit (initial): write readme file
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git reset --hard 9d42218
HEAD is now at 9d42218 add hello
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# cat readme 
hello
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit#
```

## Work area and temporary storage area

first,`git add`put the file to the temporary storage area
second,`git commit`submit all the contents of the temporary to the current branch

## Undo changes

scenario:when you mess up the contents of a file in the workspace 

