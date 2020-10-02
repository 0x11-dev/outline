// @flow
import addHours from "date-fns/add_hours";
import Router from "koa-router";
import { capitalize } from "lodash";
import Sequelize from "sequelize";
import { auth0Auth } from "../../shared/utils/routeHelpers";
import * as AUTH0 from "../auth0";
import auth from "../middlewares/authentication";
import {
  Authentication,
  Collection,
  Integration,
  User,
  Event,
  Team,
} from "../models";
import { getCookieDomain } from "../utils/domains";

const Op = Sequelize.Op;
const router = new Router();

// start the oauth process and redirect user to auth0
router.get("auth0", async (ctx) => {
  const state = Math.random().toString(36).substring(7);

  ctx.cookies.set("state", state, {
    httpOnly: false,
    expires: addHours(new Date(), 1),
    domain: getCookieDomain(ctx.request.hostname),
  });
  ctx.redirect(auth0Auth(state));
});

// signin callback from auth0
router.get("auth0.callback", auth({ required: false }), async (ctx) => {
  const { code, error, state } = ctx.request.query;
  ctx.assertPresent(code || error, "code is required");
  ctx.assertPresent(state, "state is required");

  if (state !== ctx.cookies.get("state")) {
    ctx.redirect("/?notice=auth-error&error=state_mismatch");
    return;
  }
  if (error) {
    ctx.redirect(`/?notice=auth-error&error=${error}`);
    return;
  }

  const data = await AUTH0.oauthAccess(code);
  console.log(data);
  const [team, isFirstUser] = await Team.findOrCreate({
    where: {
      auth0Id: data.user.email,
    },
    defaults: {
      name: data.user.name,
      avatarUrl: data.user.picture,
    },
  });

  try {
    const [user, isFirstSignin] = await User.findOrCreate({
      where: {
        [Op.or]: [
          {
            service: "auth0",
            serviceId: data.user.email,
          },
          {
            service: { [Op.eq]: null },
            email: data.user.email,
          },
        ],
        teamId: team.id,
      },
      defaults: {
        service: "auth0",
        serviceId: data.user.email,
        name: data.user.name,
        email: data.user.email,
        isAdmin: isFirstUser,
        avatarUrl: data.user.picture,
      },
    });

    // update the user with fresh details if they just accepted an invite
    if (!user.serviceId || !user.service) {
      await user.update({
        service: "auth0",
        serviceId: data.user.email,
        avatarUrl: data.user.picture,
      });
    }

    // update email address if it's changed in auth0
    if (!isFirstSignin && data.user.email !== user.email) {
      await user.update({ email: data.user.email });
    }

    if (isFirstUser) {
      await team.provisionFirstCollection(user.id);
      await team.provisionSubdomain(data.team.domain);
    }

    if (isFirstSignin) {
      await Event.create({
        name: "users.create",
        actorId: user.id,
        userId: user.id,
        teamId: team.id,
        data: {
          name: user.name,
          service: "auth0",
        },
        ip: ctx.request.ip,
      });
    }

    // set cookies on response and redirect to team subdomain
    ctx.signIn(user, team, "auth0", isFirstSignin);
  } catch (err) {
    if (err instanceof Sequelize.UniqueConstraintError) {
      const exists = await User.findOne({
        where: {
          service: "email",
          email: data.user.email,
          teamId: team.id,
        },
      });

      if (exists) {
        ctx.redirect(`${team.url}?notice=email-auth-required`);
      } else {
        ctx.redirect(`${team.url}?notice=auth-error`);
      }

      return;
    }

    throw err;
  }
});

export default router;
