(() => {
  const body=document.body, theme=document.getElementById('themeBtn'), menu=document.getElementById('menuBtn'), sidebar=document.getElementById('sidebar');
  const saved=localStorage.getItem('scamshield_theme'); if(saved==='light') body.classList.add('light');
  theme?.addEventListener('click',()=>{body.classList.toggle('light');localStorage.setItem('scamshield_theme',body.classList.contains('light')?'light':'dark');theme.textContent=body.classList.contains('light')?'☀':'☾'});
  menu?.addEventListener('click',()=>sidebar?.classList.toggle('open'));
  window.showToast=(msg)=>{const t=document.getElementById('toast');if(!t)return;t.textContent=msg;t.classList.add('show');clearTimeout(window.__toast);window.__toast=setTimeout(()=>t.classList.remove('show'),2600)};
  document.querySelectorAll('[data-toast]').forEach(x=>x.addEventListener('click',()=>showToast(x.dataset.toast)));
  const textarea=document.getElementById('content'), counter=document.getElementById('counter');
  if(textarea&&counter){const update=()=>counter.textContent=`${textarea.value.length} / 5000 characters`;textarea.addEventListener('input',update);update();}
  const typeInput=document.getElementById('input_type');
  document.querySelectorAll('.input-tab').forEach(tab=>tab.addEventListener('click',()=>{document.querySelectorAll('.input-tab').forEach(x=>x.classList.remove('active'));tab.classList.add('active');if(typeInput)typeInput.value=tab.dataset.type;const examples={message:'Paste suspicious SMS, DM or message here...',email:'Paste the email body, sender text and links here...',conversation:'Paste the full conversation here...',url:'Paste a suspicious URL here...'};if(textarea)textarea.placeholder=examples[tab.dataset.type]}));
  const upload=document.getElementById('uploadBtn'), file=document.getElementById('fileInput'); upload?.addEventListener('click',()=>file?.click()); file?.addEventListener('change',async()=>{const f=file.files?.[0];if(!f)return;if(f.size>1024*1024){showToast('File is larger than 1 MB');return;}if(textarea)textarea.value=await f.text();textarea?.dispatchEvent(new Event('input'));showToast(`${f.name} loaded`)});
  const demoText={
    'Banking Scam':'Your SBI account access has been suspended due to pending KYC. Verify immediately at http://sbi.kyc-verification.xyz/login and share OTP.',
    'Job Scam':'Congratulations! Part-time work from home approved. Earn Rs 4000 daily by liking YouTube videos. Pay Rs 1000 security fee to start.',
    'Lottery Scam':'Congratulations! You have won Rs 25,00,000 in KBC Lucky Draw. Pay Rs 12,500 processing fee immediately to claim your reward.',
    'Delivery Scam':'India Post: Your parcel is on hold due to missing house number. Update your delivery address at http://indiapost-update.xyz immediately.',
    'Tech Support':'Microsoft Security Alert: Your computer is infected with spyware. Install AnyDesk and contact support at 9876543210 immediately.',
    'Legitimate':'SBI: Dear customer, your account was credited with Rs 1,200 via UPI from Aman. Available balance is Rs 14,500.'
  };
  document.querySelectorAll('[data-demo]').forEach(btn=>btn.addEventListener('click',()=>{if(textarea){textarea.value=demoText[btn.dataset.demo]||'';textarea.dispatchEvent(new Event('input'));document.getElementById('scanner')?.scrollIntoView({behavior:'smooth',block:'start'});showToast(`${btn.dataset.demo} example loaded`)}}));
  const use=document.getElementById('useExample');use?.addEventListener('click',()=>{if(textarea){textarea.value='Your bank account will be suspended today. Verify your KYC immediately using this link: http://secure-check.example/login';textarea.dispatchEvent(new Event('input'));showToast('Example loaded')}});
})();


// Avatar account menu
(() => {
  const button = document.getElementById("accountMenuBtn");
  const menu = document.getElementById("accountMenu");
  if (!button || !menu) return;
  const close = () => {
    menu.hidden = true;
    button.setAttribute("aria-expanded", "false");
  };
  button.addEventListener("click", (event) => {
    event.stopPropagation();
    menu.hidden = !menu.hidden;
    button.setAttribute("aria-expanded", String(!menu.hidden));
  });
  document.addEventListener("click", (event) => {
    if (!menu.contains(event.target) && event.target !== button) close();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") close();
  });
})();
