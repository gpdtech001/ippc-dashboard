# IPPC - Reporting and Analytics Dashboard

A comprehensive PHP-based reporting and analytics dashboard for IPPC with advanced user management, role-based access control, and data visualization capabilities using AdminLTE for styling.

## Features

- **User Authentication**: Login with username or email, remember password functionality
- **Role-Based Access Control**:
  - **Admin**: Full access to all data and user management
  - **RZM (Rhapsody Zonal Manager)**: Access limited to their assigned zone
- **User Registration**: Different registration fields based on role
- **Dashboard**: Overview of users, zones, and groups with role-based filtering
- **User Management**: Admin panel for managing users
- **Profile Management**: Users can update their profile information
- **JSON Database**: All data stored in JSON files (no external database required)

## Project Structure

```
/
├── index.php              # Main entry point, redirects to login/dashboard
├── login.php              # Login page
├── register.php           # User registration page
├── dashboard.php          # Main dashboard with role-based content
├── user_management.php    # Admin user management page
├── profile.php            # User profile management
├── logout.php             # Logout handler
├── config.php             # Configuration and utility functions
├── users.json             # User data storage
├── zones.json             # Zone data (provided)
└── README.md             # This file
```

## Installation

1. Place all files in your web server's document root (e.g., `/Applications/XAMPP/xamppfiles/htdocs/ppc/`)
2. Ensure PHP has write permissions to the directory containing `users.json`
3. Start your web server (XAMPP, Apache, etc.)

## Usage

### First Time Setup

1. Navigate to the application URL
2. Register a new account:
   - For RZM: Fill in all required fields including region and zone selection
   - For Admin: Basic registration fields only

### User Roles

#### RZM (Rhapsody Zonal Manager)
- Can only view data from their assigned region and zone
- Can manage their profile
- Limited access to user information

#### Admin
- Can view all users, regions, and zones
- Can manage all users (edit roles, delete users)
- Full access to all system features

### Zone Structure

The system uses the provided `zones.json` file which contains:
- Multiple regions (Region 1, Region 2, etc.)
- Each region has multiple zones
- Each zone contains groups
- RZM users are assigned to specific zones and can only see their zone's data

## Security Features

- Password hashing using PHP's `password_hash()`
- Session-based authentication
- Input sanitization
- Role-based access control
- Remember token system for persistent login

## Technical Details

### Database
- Uses JSON files for data storage
- `users.json`: Stores user accounts and profiles
- `zones.json`: Contains zone hierarchy and group information

### Dependencies
- PHP 7.0+
- AdminLTE 3.2.0 (via CDN)
- Bootstrap 4.6.1 (via CDN)
- jQuery 3.6.0 (via CDN)
- Font Awesome 6.0.0 (via CDN)

### Session Management
- Session timeout: 24 hours
- Remember token: 30 days
- Automatic cleanup on logout

## API Functions

The `config.php` file provides utility functions:
- `getUsers()`: Retrieve all users
- `saveUsers($users)`: Save users array
- `getUserById($id)`: Get user by ID
- `getUserByUsername($username)`: Get user by username
- `getUserByEmail($email)`: Get user by email
- `hashPassword($password)`: Hash password
- `verifyPassword($password, $hash)`: Verify password

## Browser Support

- Chrome 70+
- Firefox 65+
- Safari 12+
- Edge 79+

## Contributing

1. Follow PHP coding standards
2. Use meaningful variable names
3. Add comments for complex logic
4. Test all user roles and scenarios

## License

This project is for educational/internal use only.
