---
layout: default
permalink: /
---

## Posts

<ul>
  {% for post in site.posts %}
    <li>
      <span class="date">{{ post.date | date: '%d %b %Y' }}</span> - <a href="{{ post.url }}">{{ post.title }}</a>
    </li>
  {% endfor %}
</ul>
