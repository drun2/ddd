import asyncio
import re
import aiohttp
import logging
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties

# Настройка логирования
logging.basicConfig(level=logging.INFO)

# --- НАСТРОЙКИ (СЮДА ВСТАВЛЯТЬ КЛЮЧИ) ---
BOT_TOKEN = "your tg bot token" 
VT_API_KEY = "your VIRUSTOTAL_API token" 

bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()

URL_REGEX = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"

async def check_url_virustotal(url: str) -> dict:
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    async with aiohttp.ClientSession() as session:
        submit_url = "https://www.virustotal.com/api/v3/urls"
        payload = {"url": url}
        async with session.post(submit_url, data=payload, headers=headers) as resp:
            if resp.status != 200:
                return {"error": "Ошибка API или неверный ключ."}
            result = await resp.json()
            analysis_id = result.get("data", {}).get("id")

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(15): 
            await asyncio.sleep(2)
            async with session.get(analysis_url, headers={"x-apikey": VT_API_KEY}) as resp:
                report = await resp.json()
                if report.get("data", {}).get("attributes", {}).get("status") == "completed":
                    return {"stats": report["data"]["attributes"]["stats"]}
        return {"error": "Тайм-аут проверки."}

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer("Привет! Пришли мне ссылку, и я проверю её на вирусы.")

@dp.message(F.text)
async def process_links(message: types.Message):
    urls = [match[0] for match in re.findall(URL_REGEX, message.text)]
    if not urls: return
    
    for url in urls:
        status_msg = await message.answer(f"🔍 Проверяю: {url}...")
        result = await check_url_virustotal(url)
        
        if "error" in result:
            await status_msg.edit_text(f"❌ Ошибка: {result['error']}")
            continue
            
        res = result["stats"]
        text = (f"🔗 <b>URL:</b> {url}\n"
                f"👿 Вредоносных: {res['malicious']}\n"
                f"⚠️ Подозрительных: {res['suspicious']}\n"
                f"✅ Безопасных: {res['harmless']}")
        await status_msg.edit_text(text, disable_web_page_preview=True)

async def main():
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)

if __name__ == "__main__":

    asyncio.run(main())
