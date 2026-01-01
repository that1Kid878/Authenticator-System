## Authenticator System
A backend central authentication system demonstrated by a CLI client, designed to show real world authentication concepts such as JWTs and API-client communication

### Motivation
I built this project to expand my knowledge of authentication systems, and how they work
This included information such as:
- Password hashing
- Token-based authentication
- Stateless API design
- Client-Server communication

### System Architecture
> [CLI] -HTTP Requests-> [Server] ---> [Database]
#### Responsibilities
- **CLI**: User interaction and token storage
- **Server**: Authentication logic
- **Database**: Stores user data and refresh token records

### Tech Stack
- Language: Python
- API Framework: FastAPI
- Auth: JWT, bcrypt
- Database: PostgresQL

### System Flow
1. User runs login command in CLI
2. Credentials sent to API
3. API verifies user from database
4. Access and refresh token generated
5. CLI stores tokens

### Key Design Decisions
#### Why JWT instead of server-side sessions?
It is stateless and easier to scale horizaontally
#### Why separate access and refresh tokens?
Access tokens have a shorter lifespan which makes it safer when hacker get a hold of it. This is also the modern industry practice due to the safety it provides
#### Why a CLI instead of a web frontend?
Less time spent on web design, allowing me to focus more on doing the backend

### License
Educational/ Portfolio Use
