- what is git?
git is the world's most advanced distributed version control system.

- Install git on kali
```c
apt-get install git
```
sometimes kali pre-installed

- create your respository
```c
root@gt:~/Git/Keep-learning/myGit/practiEnv# mkdir learngit
root@gt:~/Git/Keep-learning/myGit/practiEnv# cd learngit/
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# pwd
/root/Git/Keep-learning/myGit/practiEnv/learngit
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git init 
Initialized empty Git repository in /root/Git/Keep-learning/myGit/practiEnv/learngit/.git/
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# ls -a
.  ..  .git
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# 
```

- add the file to the repository

```c
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# touch readme
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# echo "git is a version control system" > readme 
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# cat readme 
git is a version control system
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git add readme 
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# git commit -m "write readme file"
[master (root-commit) 964756f] write readme file
 1 file changed, 1 insertion(+)
 create mode 100644 readme
root@gt:~/Git/Keep-learning/myGit/practiEnv/learngit# 
```

first,`git add <file>`
second,`git commite -m "xxxx"`
