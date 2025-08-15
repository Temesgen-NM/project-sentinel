# Project-Sentinel Refactoring TODO

## Phase 1: Simplify the Project Structure
- [ ] Delete src/sentinel/api/v1/analytics.py
- [ ] Delete src/sentinel/api/v1/threats.py
- [ ] Empty src/sentinel/core/models.py (keep the file but remove all content)
- [ ] Delete src/sentinel/middleware/ directory and security.py
- [ ] Delete src/sentinel/services/elasticsearch_service.py

## Phase 2: Implement Core Data Processing Logic
- [ ] Replace src/sentinel/main.py with new startup code
- [ ] Replace src/sentinel/services/threat_processor.py with new processing logic

## Phase 3: Implement Single Useful API Endpoint
- [ ] Replace src/sentinel/api/v1/endpoints.py with new endpoints

## Phase 4: Final Configuration Cleanup
- [ ] Replace requirements.txt with minimal dependencies
- [ ] Replace infra/honeypot/cowrie.cfg with minimal configuration
