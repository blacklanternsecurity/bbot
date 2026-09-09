import discord
from discord.ext import commands

from bbot.scanner import Scanner


class BBOTDiscordBot(commands.Cog):
    """
    A simple Discord bot capable of running a BBOT scan.

    To set up:
        1. Go to Discord Developer Portal (https://discord.com/developers)
        2. Create a new application
        3. Create an invite link for the bot, visit the link to invite it to your server
            - Your Application --> OAuth2 --> URL Generator
                - For Scopes, select "bot"
                - For Bot Permissions, select:
                    - Read Messages/View Channels
                    - Send Messages
        4. Turn on "Message Content Intent"
            - Your Application --> Bot --> Privileged Gateway Intents --> Message Content Intent
        5. Copy your Discord Bot Token and put it at the top of this file
            - Your Application --> Bot --> Reset Token
        6. Run this script

    To scan evilcorp.com, you would type:

        /scan evilcorp.com

    Results will be output to the same channel.
    """

    def __init__(self):
        self.current_scan = None

    @commands.command(name="scan", description="Scan a target with BBOT.")
    async def scan(self, ctx, target: str):
        # stop any existing scan
        if self.current_scan is not None:
            self.current_scan.stop()
        await ctx.send(f"Starting scan against **{target}**")

        # create scan instance
        self.current_scan = Scanner(target, presets=["subdomain-enum"])

        # iterate through results and send them to the channel
        num_events = 0
        async for event in self.current_scan.async_start():
            # format findings differently to show severity
            if event.type == "FINDING":
                severity = event.data.get("severity", "INFO")
                description = event.data.get("description", "")
                event_text = f"`[FINDING]` [{severity}] **{description}**"
            else:
                event_text = f"`[{event.type}]` **`{event.data}`**"
            await ctx.send(event_text)
            num_events += 1

        await ctx.send(f"Finished scan against **{target}**. {num_events:,} results.")
        self.current_scan = None

    @commands.command(name="stop", description="Stop the current scan.")
    async def stop(self, ctx):
        if self.current_scan is None:
            await ctx.send("No scan is currently running.")
            return
        self.current_scan.stop()
        await ctx.send("Scan stopped.")


if __name__ == "__main__":
    intents = discord.Intents.default()
    intents.message_content = True
    bot = commands.Bot(command_prefix="/", intents=intents)

    @bot.event
    async def on_ready():
        print(f"We have logged in as {bot.user}")
        await bot.add_cog(BBOTDiscordBot())

    bot.run("DISCORD_BOT_TOKEN_HERE")
