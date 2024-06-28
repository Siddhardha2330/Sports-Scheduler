const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const connectEnsureLogin = require('connect-ensure-login');
const { v4: uuidv4 } = require('uuid');
const db = require('./models');
const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 10;
const flash = require('connect-flash');
const csrf = require('csurf');

app.use(cookieParser());
app.use(session({
  secret: 'your_secret_here',
  resave: false, 
  saveUninitialized: false, 
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000 
  }
}));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());


app.use(csrf({ cookie: true }));


app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});


passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const admin = await db.Admin.findByPk(id);
    if (admin) {
      done(null, { id: admin.id, name: admin.name, type: 'admin' });
      return;
    }

    const player = await db.Player.findByPk(id);
    if (player) {
      done(null, { id: player.id, name: player.name, type: 'player' });
      return;
    }

    done(new Error('User not found'));
  } catch (error) {
    done(error);
  }
});
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

passport.use('admin-local', new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    const admin = await db.Admin.findOne({ where: { email } });
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return done(null, false, { errorMessage: 'Invalid email or password' });
    }
    return done(null, { id: admin.id, name: admin.name, type: 'admin' });
  } catch (error) {
    return done(error);
  }
}));


passport.use('player-local', new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    const player = await db.Player.findOne({ where: { email } });
    if (!player || !(await bcrypt.compare(password, player.password))) {
      return done(null, false, { errorMessage: 'Invalid email or password' });
    }
    return done(null, { id: player.id, name: player.name, type: 'player' });
  } catch (error) {
    return done(error);
  }
}));


app.get('/login', (req, res) => {
  const csrfToken = req.csrfToken();
  const errorMessage = req.flash('error');
  console.log(errorMessage[0]);
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).send('Internal Server Error');
    }
    res.render('login', { errorMessage, csrfToken });
  });
  
});

app.post('/login', (req, res, next) => {
  const csrfToken = req.csrfToken();
  const { email, password } = req.body;

  if (!email || !password) {
    req.flash('error', 'Email and password are required');
    return res.redirect('/login');
  }

  passport.authenticate(['admin-local', 'player-local'], (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      req.flash('error', 'Invalid email or password');
      return res.redirect('/login');
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      req.session.user = user;
      if (user.type === 'admin') {
        return res.redirect('/admin_dashboard');
      } else if (user.type === 'player') {
        return res.redirect('/player_dashboard');
      } else {
        req.flash('error', 'Invalid user type');
        return res.redirect('/login');
      }
    });
  })(req, res, next);
});

// Routes
app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Error during logout:', err);
      return res.status(500).send('Internal Server Error');
    }
    req.session.destroy((err) => {
      if (err) {
        console.error('Error destroying session:', err);
        return res.status(500).send('Internal Server Error');
      }
      res.redirect('/login');
    });
  });
});


app.post('/createsport', async (req, res) => {
  const csrfToken = req.csrfToken();
  const user = req.session.user;
  if (!user || user.type !== 'admin') {
    return res.redirect('/login');
  }

  try {
    const { name } = req.body;
    const creator = user.name;
    const newSport = await db.Sport.create({ name, creator });
    res.redirect("/admin_dashboard");
  } catch (error) {
    console.error('Error creating sport:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.get('/signup', (req, res) => {
  const csrfToken = req.csrfToken();
  const errorMessage = req.flash('error');
  console.log(errorMessage, csrfToken);
  res.render('login', { errorMessage, csrfToken });
});

app.post('/signup', async (req, res) => {
  const csrfToken = req.csrfToken();
  try {
    const { name, email, password, confirmPassword, userType } = req.body;

    if (password !== confirmPassword) {
      req.flash('error', 'Passwords do not match');
      return res.redirect('/signup');
    }

    const existingAdmin = await db.Admin.findOne({ where: { email } });
    const existingPlayer = await db.Player.findOne({ where: { email } });

    if (existingAdmin || existingPlayer) {
      req.flash('error', 'Email already exists');
      return res.redirect('/signup');
    }

    const existingAdminUsername = await db.Admin.findOne({ where: { name } });
    const existingPlayerUsername = await db.Player.findOne({ where: { name } });

    if (existingAdminUsername || existingPlayerUsername) {
      req.flash('error', 'Username already exists');
      return res.redirect('/signup');
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    let newUser;
    if (userType === 'admin') {
      newUser = await db.Admin.create({ name, email, password: hashedPassword });
    } else if (userType === 'player') {
      newUser = await db.Player.create({ name, email, password: hashedPassword });
    } else {
      req.flash('error', 'Invalid user type');
      return res.redirect('/signup');
    }

    req.session.user = { id: newUser.id, name: newUser.name, type: userType };
    res.redirect('/login');
  } catch (error) {
    console.error('Error signing up:', error);
    req.flash('error', 'Internal Server Error');
    res.redirect('/signup');
  }
});

// Route for creating sessions
app.get('/createsession', (req, res) => {
  const csrfToken = req.csrfToken();
  const user = req.session.user;

  if (!user) {
    return res.redirect('/login');
  }

  res.render('createsession', { user, csrfToken });
});

app.post('/createsession/:sportName', async (req, res) => {
  const csrfToken = req.csrfToken();
  try {
    const {
      place,
      date,
      begintime,
      endtime,
      playerscount,
      venue
    } = req.body;
    const sport = req.params.sportName;
    const creator = req.session.user.name;

 
    let players = req.body['players[]'];
    if (!players) {
      return res.status(400).json({ message: 'Players field is required and must be an array' });
    }


    if (!Array.isArray(players)) {
      players = [players];
    }


    const validPlayers = players.filter(player => player.trim() !== '');


    const remainingPlayersCount = playerscount - validPlayers.length;


    const newSession = await db.Session.create({
      creator,
      sport,
      place,
      date,
      begintime,
      endtime,
      playerscount: remainingPlayersCount,
      venue
    });

    const matchPromises = validPlayers.map(player => db.Match.create({
      creator,
      sport,
      place,
      date,
      begintime,
      endtime,
      player,
      venue
    }));

    await Promise.all(matchPromises);

    res.redirect(`/opensessions/${sport}`);
  } catch (error) {
    console.error('Error creating session:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.get('/opensessions/:sportName', async (req, res) => {
  const csrfToken = req.csrfToken();
  const errorMessage = req.flash('error');
  if (!req.session.user) {
    res.redirect("/login");
  }
  try {
    const { sportName } = req.params;
    const sport = await db.Sport.findOne({ where: { name: sportName } });
    if (!sport) {
      return res.status(404).send('Sport not found');
    }

    const sessions = await db.Session.findAll({ where: { sport: sport.name } });
    const user = req.session.user;

    const matches = await db.Match.findAll({ where: { player: user.name } });
   

    const yourSessions = sessions.filter(session => session.creator === user.name);
    const otherSessions = sessions.filter(session => session.creator !== user.name);

    res.render('opensessions', { sport, yourSessions, otherSessions, user, csrfToken, errorMessage });
  } catch (error) {
    console.error('Error fetching sessions:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/joinsession/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = await db.Session.findByPk(sessionId);
    const playerName = req.session.user.name;

    if (!session) {
      return res.status(404).send('Session not found');
    }

    const overlappingSessions = await db.Match.findAll({
      where: {
        player: playerName,
        date: session.date,
        begintime: {
          [db.Sequelize.Op.lte]: session.endtime
        },
        endtime: {
          [db.Sequelize.Op.gte]: session.begintime
        }
      }
    });

    if (overlappingSessions.length > 0) {
      req.flash('error', 'You have already joined another session at this time.');
      return res.redirect(`/opensessions/${session.sport}`);
    }

    await db.Match.create({
      creator: session.creator,
      sport: session.sport,
      place: session.place,
      date: session.date,
      begintime: session.begintime,
      endtime: session.endtime,
      player: playerName,
      venue: session.venue,
     
    });

    await session.update({ playerscount: session.playerscount - 1 });

    res.redirect(`/opensessions/${session.sport}`);
  } catch (error) {
    console.error('Error joining session:', error);
    res.status(500).send('Internal Server Error');
  }
});


app.get('/reports', (req, res) => {
  const csrfToken = req.csrfToken();
  const user = req.session.user;
  if (!user || user.type !== 'admin') {
    return res.redirect('/login');
  }
  console.log(user);
  res.render('reports', { user, csrfToken });
});

app.post('/generateReports', async (req, res) => {
  const csrfToken = req.csrfToken();
  const { startDate, endDate } = req.body;
  const user = req.session.user;

  if (!user || user.type !== 'admin') {
    return res.redirect('/login');
  }

  try {
    const sessionsCount = await db.Session.count({
      where: {
        date: {
          [db.Sequelize.Op.between]: [startDate, endDate]
        }
      }
    });

    const sportsPopularity = await db.Session.findAll({
      attributes: [
        'sport',
        [db.Sequelize.fn('COUNT', db.Sequelize.col('sport')), 'count']
      ],
      where: {
        date: {
          [db.Sequelize.Op.between]: [startDate, endDate]
        }
      },
      group: ['sport']
    });

    res.render('report_results', { user, sessionsCount, sportsPopularity, csrfToken });
  } catch (error) {
    console.error('Error generating reports:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/deleteSession/:sport', async (req, res) => {
  const csrfToken = req.csrfToken();
  const { reason, sessionId } = req.body;
  const user = req.session.user;
  const { sport } = req.params;

  try {
    const session = await db.Session.findByPk(sessionId);

    if (!session) {
      return res.status(404).json({ message: 'Session not found' });
    }

    if (session.creator !== user.name) {
      return res.status(403).json({ message: 'You are not authorized to delete this session' });
    }

    await session.update({ deleted: true, reason });

    res.redirect(`/opensessions/${sport}`);
  } catch (error) {
    console.error('Error deleting session:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
app.post('/change-password', async (req, res) => {
  const { currentPassword, newPassword, confirmNewPassword } = req.body;
  const userId = req.session.user.id;

  if (newPassword !== confirmNewPassword) {
      req.flash('error', 'Passwords do not match');
      return res.redirect(`/${req.session.user.type}_dashboard?changePassword=true`);
  }

  try {
      let user;
      if (req.session.user.type === "admin") {
          user = await db.Admin.findByPk(userId);
      } else {
          user = await db.Player.findByPk(userId);
      }

      const match = await bcrypt.compare(currentPassword, user.password);
      if (!match) {
          req.flash('error', 'Current password is incorrect');
          return res.redirect(`/${req.session.user.type }_dashboard?changePassword=true`);
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      await user.save();

      req.flash('success', 'Password changed successfully');
      res.redirect(`/${req.session.user.type }_dashboard`);
  } catch (err) {
      console.error(err);
      req.flash('error', 'An error occurred');
      res.redirect(`/${req.session.user.type }_dashboard?changePassword=true`);
  }
});

app.get('/admin_dashboard', async (req, res) => {
  const csrfToken = req.csrfToken();
  const user = req.session.user;
  if (!user || user.type !== 'admin') {
      return res.redirect('/login');
  }

  try {
      const sports = await db.Sport.findAll();
      const errorMessage = req.flash('error');
      const showChangePasswordModal = req.query.changePassword === 'true';
      res.render('admin_dashboard', { sports, admin: { name: user.name,type:user.type }, csrfToken, errorMessage, showChangePasswordModal });
  } catch (error) {
      console.error('Error fetching sports:', error);
      res.status(500).send('Internal Server Error');
  }
});

app.get('/player_dashboard', async (req, res) => {
  const user = req.session.user;
  const csrfToken = req.csrfToken();
  if (!user || user.type !== 'player') {
    return res.redirect('/login');
  }
  try {
    const sports = await db.Sport.findAll();
    const errorMessage = req.flash('error');
    const showChangePasswordModal = req.query.changePassword === 'true';
    res.render('player_dashboard', { sports, admin: { name: user.name,type:user.type }, csrfToken, errorMessage, showChangePasswordModal });
  } catch (error) {
    console.error('Error fetching sports:', error);
    res.status(500).send('Internal Server Error');
  }
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
}

module.exports = app;