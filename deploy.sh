#!/bin/bash

set -e

echo ""
echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║                                                                    ║"
echo "║              RockyCrypt Production Deployment Script              ║"
echo "║                   NSE Kenya Premium Analytics                      ║"
echo "║                                                                    ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Check prerequisites
echo -e "${YELLOW}[1/7] Checking prerequisites...${NC}"
command -v docker >/dev/null 2>&1 || { echo -e "${RED}Docker is required but not installed.${NC}"; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo -e "${RED}Docker Compose is required but not installed.${NC}"; exit 1; }
echo -e "${GREEN}✓ Docker and Docker Compose installed${NC}"

# Step 2: Create necessary directories
echo -e "${YELLOW}[2/7] Creating directories...${NC}"
mkdir -p data logs ssl
echo -e "${GREEN}✓ Directories created${NC}"

# Step 3: Check environment file
echo -e "${YELLOW}[3/7] Checking environment configuration...${NC}"
if [ ! -f .env.production ]; then
    echo -e "${RED}Error: .env.production file not found${NC}"
    echo "Please create .env.production with required variables:"
    echo ""
    echo "ROCKYCRYPT_PRODUCTION=true"
    echo "ROCKYCRYPT_ADMIN_SECRET=your_secure_secret"
    echo "ROCKYCRYPT_JWT_SECRET=your_secure_jwt_secret"
    echo "ROCKYCRYPT_CORS_ORIGINS=https://yourdomain.com"
    echo ""
    exit 1
fi
echo -e "${GREEN}✓ Environment file found${NC}"

# Step 4: Load environment
echo -e "${YELLOW}[4/7] Loading environment variables...${NC}"
set -a
# shellcheck disable=SC1091
source .env.production
set +a
echo -e "${GREEN}✓ Environment variables loaded${NC}"

# Step 5: Build Docker image
echo -e "${YELLOW}[5/7] Building Docker image...${NC}"
docker-compose build --no-cache
echo -e "${GREEN}✓ Docker image built${NC}"

# Step 6: Start services
echo -e "${YELLOW}[6/7] Starting services...${NC}"
docker-compose up -d --pull always
echo -e "${GREEN}✓ Services started${NC}"

# Step 7: Verify deployment
echo -e "${YELLOW}[7/7] Verifying deployment...${NC}"
sleep 5

echo "Checking backend health..."
if curl -sf http://localhost:8000/api/market-status > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Backend is healthy${NC}"
else
    echo -e "${RED}✗ Backend health check failed${NC}"
    echo "Checking logs..."
    docker-compose logs rockycrypt --tail=20
    exit 1
fi

# Success message
echo ""
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║                                                                    ║"
echo "║           🎉 RockyCrypt Deployment Successful! 🎉                 ║"
echo "║                                                                    ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📍 DEPLOYMENT DETAILS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Frontend:         https://yourdomain.com"
echo "API Endpoint:     https://yourdomain.com/api"
echo "Admin Panel:      https://yourdomain.com/admin"
echo ""
echo "Backend Port:     8000 (internal)"
echo "Nginx Port:       80/443 (external)"
echo ""
echo "Data Directory:   ./data"
echo "Logs Directory:   ./logs"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔐 CREDENTIALS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Admin Secret:     ${ROCKYCRYPT_ADMIN_SECRET:+configured}${ROCKYCRYPT_ADMIN_SECRET:-MISSING}"
echo "JWT Secret:       ${ROCKYCRYPT_JWT_SECRET:+configured}${ROCKYCRYPT_JWT_SECRET:-MISSING}"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 USEFUL COMMANDS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "View logs:"
echo "  docker-compose logs -f rockycrypt"
echo ""
echo "Container status:"
echo "  docker ps"
echo ""
echo "Monitor resources:"
echo "  docker stats"
echo ""
echo "Stop services:"
echo "  docker-compose down"
echo ""
echo "Rebuild and redeploy:"
echo "  docker-compose up -d --build --pull always"
echo ""
echo "View Docker disk usage:"
echo "  docker system df"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ NEXT STEPS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Verify SSL certificates are in ./ssl/ directory"
echo "2. Update nginx.conf with your domain name"
echo "3. Test API endpoints: curl https://yourdomain.com/api/market-status"
echo "4. Set up monitoring and alerting"
echo "5. Configure backups for ./data directory"
echo "6. Set up log rotation"
echo ""

echo "For detailed troubleshooting, see DEPLOYMENT_GUIDE.md"
echo ""
