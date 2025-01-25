<h1 align="center"> Contributing StarShop Contracts</h1>

# 📝 Table of Contents
 
1. 🚀 [Introduction](#introduction)
2. 🏆 [Contributing](#contributing)
3. 🎯 [Common Mistakes](#common-mistakes)
4. 🔗 [Branches](#branches)


--- 
## 🚀 Introduction
This document outlines the rules and guidelines for contributing to the Smart Contracts of the StarShop project. By following these rules, contributors ensure consistent development practices and smooth collaboration across the team.

## 🏆 Contributing 
We welcome contributions from the community! Here's how you can help:

1. **Clone and Fork Repo:** Click the Fork button in the top-right corner to create a copy of the repository under your account.   

    - <a href="https://github.com/StarShopCr/StarShop-Contracts" target="_blank"> StarShop Repo</a>

---

2. **Clone the Fork:** 
    - Clone the forked repository to your local machine by running the following command:

    ```bash
   git clone https://github.com/YOUR_USERNAME/StarShop-Contracts.git
   ```

    - Replace `YOUR_USERNAME` with your GitHub username.

---

3. **Create a new branch or use the main branch:** When modifying contracts kindly make sure the formatting is correct and all tests pass successfully.

    - Create a branch name based on the type of change (`feat/name-related-issue`, `fix/name-related-issue`, `bug/name-related-issue`).

    ```
    git checkout -b branch-name
    ```
    - One of ideas on how to implement it for the branch name:

        > `feat/implement-contract` or `fix/bottom-bug`.
 

---

4. **Commit:** Commit your changes.

    1. **git add (file-name) / git add .**
    2. **git commit -m "[type] description"**

    - Example: 
    ```
    git add ImplementContract
    ```
    ```
    git commit -m feat/implement-smart-contract
    ```

---

5. **Push fork:** Push to your fork and submit a pull request on our `main` branch. Please provide us with some explanation of why you made the changes you made. For new features make sure to explain a standard use case to us.

- `Always remember to do git pull`

- Push your changes to your forked repository:
    ```bash
   git push origin your-branch-name
   ```
   > Replace `your-branch-name` with the name of your branch.

- Example: 
    ```bash
    git push origin fix/bug-fix
    ```
    
---

## 🎯 **Common Mistakes**
1. **Local changes without saving.**
    - Save changes temporarily
    ```bash
    git stash
    ```
2. **Then update and recover your changes.**
    ```bash
    git stash pop
    ```
3. **Untracked files causing conflict.**
    - Delete them if you don't need them
    ```bash
    rm filename
    ```

---

# **🔗 Branches**
1. There must be a `main` branch, used only for the releases.
2. Avoid long descriptive names for long-lived branches.
3. Use kebab-case (no CamelCase).
4. Use grouping tokens (words) at the beginning of your branch names (in a similar way to the `type` of commit).
5. Define and use short lead tokens to differentiate branches in a way that is meaningful to your workflow.
6. Use slashes to separate parts of your branch names.
7. Remove your branch after merging it if it is not important

**Examples:**

| **Default Command**      |                                 **Branch**                                      |  
|-----------------------|-----------------------------------------------------|  
| `git checkout -b`        |  feat/implement-contract      |  
| `git checkout -b`       | fix/fix-file-contract            |  
| `git checkout -b`       | bug/bug-in-contract                        |  
 | `git checkout -b`       | doc/add-document-for-contract                        | 

---

#### **Thank you for wanting to contribute to StarShop, we are glad that you have chosen us as your project of choice and we hope that you continue contributing along this path, so that together we can leave a mark at the top!**
