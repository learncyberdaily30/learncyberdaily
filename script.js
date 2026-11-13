const toggle=document.querySelector('.menu-toggle'),nav=document.querySelector('#nav');
toggle.addEventListener('click',()=>{const open=nav.classList.toggle('open');toggle.setAttribute('aria-expanded',open)});
nav.querySelectorAll('a').forEach(a=>a.addEventListener('click',()=>nav.classList.remove('open')));
const filters=[...document.querySelectorAll('.filter')],cards=[...document.querySelectorAll('.article-card')],empty=document.querySelector('#emptyState');
function filterArticles(category){let count=0;cards.forEach(card=>{const show=category==='All'||card.dataset.category===category;card.hidden=!show;if(show)count++});empty.hidden=count!==0;filters.forEach(b=>b.classList.toggle('active',b.dataset.category===category))}
filters.forEach(b=>b.addEventListener('click',()=>filterArticles(b.dataset.category)));
document.querySelectorAll('.topic-card').forEach(c=>c.addEventListener('click',()=>filterArticles(c.dataset.filter)));
const tips=['Use unique passwords and a password manager for every account.','Enable MFA wherever it is available—prefer phishing-resistant methods.','Verify links and sender details before opening unexpected messages.','Keep software and browsers updated to reduce known vulnerabilities.','Practice security tools only in systems and labs you are authorized to use.','Treat AI output as a starting point: verify facts and never paste secrets.'];
document.querySelector('#dailyTip').addEventListener('click',()=>document.querySelector('#tip').textContent=tips[Math.floor(Math.random()*tips.length)]);
document.querySelector('#year').textContent=new Date().getFullYear();