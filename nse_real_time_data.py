"""
RockyCrypt Real-Time NSE Data Module
Live market data feed with WebSocket support
"""

import asyncio
import websockets
import json
from datetime import datetime, timedelta
from typing import Dict, List, Callable, Optional
import aiohttp
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NSERealTimeDataManager:
    """Manages live NSE market data feed"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.connection = None
        self.callbacks: List[Callable] = []
        self.price_cache: Dict = {}
        self.bid_ask_cache: Dict = {}
        self.order_book_cache: Dict = {}
        self.subscribed_symbols: set = set()
        self.last_update: Dict = {}
        
    async def connect_to_nse_feed(self):
        """Connect to NSE WebSocket for live data"""
        try:
            # NSE API endpoint (replace with actual NSE WebSocket)
            uri = "wss://nse-live.example.com/api/v1/market/quotes"
            
            async with websockets.connect(uri) as websocket:
                self.connection = websocket
                logger.info("✅ Connected to NSE live data feed")
                await self._listen_for_updates()
        except Exception as e:
            logger.error(f"❌ Connection error: {e}")
            # Fallback to polling
            await self._polling_fallback()
    
    async def _listen_for_updates(self):
        """Listen for incoming market ticks"""
        try:
            async for message in self.connection:
                data = json.loads(message)
                await self._process_market_tick(data)
        except Exception as e:
            logger.error(f"Listen error: {e}")
    
    async def _polling_fallback(self):
        """Fallback: Poll NSE API every 100ms"""
        while True:
            try:
                for symbol in self.subscribed_symbols:
                    await self._fetch_live_quote(symbol)
                await asyncio.sleep(0.1)  # 100ms updates
            except Exception as e:
                logger.error(f"Polling error: {e}")
                await asyncio.sleep(1)
    
    async def _fetch_live_quote(self, symbol: str):
        """Fetch live quote from NSE API"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.nse.co.ke/api/quote/{symbol}"
                headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
                
                async with session.get(url, headers=headers, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        await self._process_market_tick(data)
        except Exception as e:
            logger.error(f"Fetch error for {symbol}: {e}")
    
    async def _process_market_tick(self, tick: Dict):
        """Process incoming market tick"""
        try:
            symbol = tick.get("symbol", "").upper()
            if not symbol:
                return
            
            # Update price cache
            self.price_cache[symbol] = {
                "symbol": symbol,
                "price": float(tick.get("lastPrice", 0)),
                "open": float(tick.get("openPrice", 0)),
                "high": float(tick.get("highPrice", 0)),
                "low": float(tick.get("lowPrice", 0)),
                "close": float(tick.get("closePrice", 0)),
                "volume": int(tick.get("totalTradedVolume", 0)),
                "value": float(tick.get("totalTradedValue", 0)),
                "change": float(tick.get("change", 0)),
                "change_pct": float(tick.get("changePercent", 0)),
                "bid": float(tick.get("bid", 0)),
                "ask": float(tick.get("ask", 0)),
                "bid_volume": int(tick.get("bidQty", 0)),
                "ask_volume": int(tick.get("askQty", 0)),
                "timestamp": datetime.now().isoformat(),
                "time": tick.get("time", ""),
            }
            
            # Update bid/ask cache
            self.bid_ask_cache[symbol] = {
                "bid": float(tick.get("bid", 0)),
                "ask": float(tick.get("ask", 0)),
                "bid_volume": int(tick.get("bidQty", 0)),
                "ask_volume": int(tick.get("askQty", 0)),
                "spread": float(tick.get("ask", 0)) - float(tick.get("bid", 0)),
                "spread_pct": ((float(tick.get("ask", 1)) - float(tick.get("bid", 0))) / 
                              float(tick.get("ask", 1))) * 100,
                "timestamp": datetime.now().isoformat()
            }
            
            # Update order book
            self.order_book_cache[symbol] = {
                "symbol": symbol,
                "bid_levels": tick.get("bidLevels", []),
                "ask_levels": tick.get("askLevels", []),
                "total_bid_volume": sum(level.get("quantity", 0) for level in tick.get("bidLevels", [])),
                "total_ask_volume": sum(level.get("quantity", 0) for level in tick.get("askLevels", [])),
                "timestamp": datetime.now().isoformat()
            }
            
            # Store last update time
            self.last_update[symbol] = datetime.now()
            
            # Trigger callbacks
            for callback in self.callbacks:
                try:
                    await callback(symbol, self.price_cache[symbol])
                except Exception as e:
                    logger.error(f"Callback error: {e}")
                    
        except Exception as e:
            logger.error(f"Tick processing error: {e}")
    
    async def get_live_quote(self, symbol: str) -> Optional[Dict]:
        """Get current live quote for symbol"""
        return self.price_cache.get(symbol.upper())
    
    async def get_all_quotes(self) -> Dict:
        """Get all cached live quotes"""
        return self.price_cache
    
    async def get_bid_ask(self, symbol: str) -> Optional[Dict]:
        """Get current bid/ask spread"""
        return self.bid_ask_cache.get(symbol.upper())
    
    async def get_order_book(self, symbol: str) -> Optional[Dict]:
        """Get order book depth"""
        return self.order_book_cache.get(symbol.upper())
    
    async def get_market_breadth(self) -> Dict:
        """Get market breadth (gainers, losers, unchanged)"""
        gainers = sum(1 for q in self.price_cache.values() if q["change_pct"] > 0)
        losers = sum(1 for q in self.price_cache.values() if q["change_pct"] < 0)
        unchanged = len(self.price_cache) - gainers - losers
        
        return {
            "gainers": gainers,
            "losers": losers,
            "unchanged": unchanged,
            "total": len(self.price_cache),
            "advance_decline_ratio": gainers / max(losers, 1)
        }
    
    def subscribe(self, symbol: str) -> None:
        """Subscribe to symbol updates"""
        self.subscribed_symbols.add(symbol.upper())
        logger.info(f"Subscribed to {symbol}")
    
    def unsubscribe(self, symbol: str) -> None:
        """Unsubscribe from symbol updates"""
        self.subscribed_symbols.discard(symbol.upper())
        logger.info(f"Unsubscribed from {symbol}")
    
    def register_callback(self, callback: Callable) -> None:
        """Register callback for price updates"""
        self.callbacks.append(callback)
    
    async def get_price_history(self, symbol: str, period: str = "1D") -> Optional[List[Dict]]:
        """Get historical price data"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.nse.co.ke/api/history/{symbol}"
                params = {"period": period}
                headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
                
                async with session.get(url, params=params, headers=headers) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception as e:
            logger.error(f"History fetch error: {e}")
        return None


# Global instance
nse_data_manager = None

async def initialize_nse_data(api_key: str = None):
    """Initialize NSE data manager"""
    global nse_data_manager
    nse_data_manager = NSERealTimeDataManager(api_key)
    asyncio.create_task(nse_data_manager.connect_to_nse_feed())
    return nse_data_manager


# FastAPI Integration
async def setup_nse_routes(app):
    """Setup NSE data routes in FastAPI app"""
    
    @app.on_event("startup")
    async def startup_nse():
        await initialize_nse_data()
    
    @app.websocket("/api/live/quote/{symbol}")
    async def websocket_live_quote(websocket, symbol: str):
        """WebSocket endpoint for live price stream"""
        await websocket.accept()
        
        async def callback(sym: str, quote: Dict):
            if sym.upper() == symbol.upper():
                await websocket.send_json(quote)
        
        nse_data_manager.register_callback(callback)
        nse_data_manager.subscribe(symbol)
        
        try:
            while True:
                quote = await nse_data_manager.get_live_quote(symbol)
                if quote:
                    await websocket.send_json(quote)
                await asyncio.sleep(0.1)
        except Exception:
            pass
        finally:
            nse_data_manager.unsubscribe(symbol)
    
    @app.get("/api/live/quote/{symbol}")
    async def get_live_quote_rest(symbol: str):
        """REST endpoint for live quote"""
        quote = await nse_data_manager.get_live_quote(symbol)
        if quote:
            return quote
        return {"error": "Symbol not found", "symbol": symbol}
    
    @app.get("/api/live/quotes")
    async def get_all_live_quotes():
        """Get all live quotes"""
        return await nse_data_manager.get_all_quotes()
    
    @app.get("/api/live/bid-ask/{symbol}")
    async def get_bid_ask(symbol: str):
        """Get bid/ask spread"""
        spread = await nse_data_manager.get_bid_ask(symbol)
        if spread:
            return spread
        return {"error": "Symbol not found"}
    
    @app.get("/api/live/orderbook/{symbol}")
    async def get_orderbook(symbol: str):
        """Get order book depth"""
        book = await nse_data_manager.get_order_book(symbol)
        if book:
            return book
        return {"error": "Symbol not found"}
    
    @app.get("/api/live/breadth")
    async def get_market_breadth():
        """Get market breadth"""
        return await nse_data_manager.get_market_breadth()
    
    @app.get("/api/live/history/{symbol}")
    async def get_price_history(symbol: str, period: str = "1D"):
        """Get historical prices"""
        history = await nse_data_manager.get_price_history(symbol, period)
        if history:
            return history
        return {"error": "No history found"}


print("[REAL-TIME NSE] Module loaded")
print("[REAL-TIME NSE] Features: Live quotes, WebSocket stream, Order book, Bid/ask spreads, Market breadth")
