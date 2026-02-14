# Orbit

**Orbit** is a self-hosted student hub that brings schedules, study sets, assignments, and chats into one calm dashboard. Built for real school workflows: focused, fast, and friendly.  

Live site (when available): `orbit.vlad-p.com`

## What Orbit includes

- **Schedule that adapts**
  - Weekly schedule view, class details, countdown to next class
  - Add after-school activities (clubs, practice, study, personal)
  - Supports different schedule styles (same every day, A/B days, block schedule)

- **Study sets**
  - Create sets, add cards, import cards in bulk (multiple delimiters)
  - Study modes: **Flashcards**, **Practice**, **Test**, **Match**

- **Chats**
  - Class threads, direct messages, and group chats
  - Lightweight, student-first messaging built into the workflow

- **Friends**
  - Add friends, manage requests
  - View a friend’s shared schedule

- **To-do and assignments**
  - Assignments tied to classes with due dates
  - Filters for active/completed and due windows

- **Profile**
  - Basic student profile and shareable profile page

## Repo layout

This repo is intentionally simple: mostly static pages plus a small Python server.

- `landing.html` , marketing/entry page  
- `signin.html` , sign-in page  
- `about.html` , project and creator info  
- `index.html` , main dashboard UI (prototype style)  
- `user.html` , public profile page  
- `prototype.html` , earlier UI prototype  
- `server.py` , local server + local data storage
- `assets/` , images and static assets

## Quick start (local)

### Requirements
- Python 3.10+ recommended

### Run
```bash
git clone https://github.com/vafc21/orbit.git
cd orbit
python3 server.py
