const crypto = require("crypto");
const mongoose = require("mongoose");
const {
  buildCaseInsensitiveEmailFilter,
  normalizeEmail,
} = require("./emailNormalization.js");
const {
  arrayHasObjectId,
  canManageBreweryInvites,
  canReadBreweryMembership,
  isBreweryAdmin,
} = require("./rolePredicates.js");

const DEFAULT_FRONTEND_BASE_URL = "https://beer-flow.vercel.app";
const INVITE_TTL_MS = 24 * 60 * 60 * 1000;
const INVITE_TOKEN_BYTES = 32;
const INVITE_TOKEN_PATTERN = /^[a-f0-9]{64}$/i;

class ServiceError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.name = "ServiceError";
    this.statusCode = statusCode;
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => {
    switch (character) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      case "'":
        return "&#39;";
      default:
        return character;
    }
  });
}

function getFrontendBaseUrl(baseUrl) {
  try {
    const parsedUrl = new URL(baseUrl || DEFAULT_FRONTEND_BASE_URL);
    return parsedUrl.origin.replace(/\/$/, "");
  } catch (error) {
    return DEFAULT_FRONTEND_BASE_URL;
  }
}

function buildInviteUrl(baseUrl, token) {
  return `${getFrontendBaseUrl(baseUrl)}/invite/${encodeURIComponent(token)}`;
}

function validateInviteToken(token) {
  return typeof token === "string" && INVITE_TOKEN_PATTERN.test(token);
}

function validateBreweryId(breweryId) {
  if (!mongoose.isValidObjectId(breweryId)) {
    throw new ServiceError("Invalid brewery ID format.", 400);
  }
}

function isDuplicateKeyError(error) {
  return Boolean(error && (error.code === 11000 || error.code === 11001));
}

function wasRecipientAccepted(delivery, recipientEmail) {
  if (!delivery || !Array.isArray(delivery.accepted)) {
    return false;
  }

  return delivery.accepted.some((acceptedRecipient) => {
    const address =
      acceptedRecipient && typeof acceptedRecipient === "object"
        ? acceptedRecipient.address
        : acceptedRecipient;
    return normalizeEmail(address) === recipientEmail;
  });
}

function getMatchedCount(result) {
  if (!result || typeof result !== "object") {
    return 0;
  }

  return result.matchedCount ?? result.n ?? 0;
}

function assertMatchedCount(result, message, statusCode) {
  if (getMatchedCount(result) === 0) {
    throw new ServiceError(message, statusCode);
  }
}

function buildAdminGrantFilter({ breweryId, authUserId, targetUserId }) {
  return {
    _id: breweryId,
    staff: targetUserId,
    admin: { $ne: targetUserId },
    $or: [{ owner: authUserId }, { admin: authUserId }],
  };
}

function buildAdminRevokeFilter({ breweryId, authUserId, targetUserId }) {
  return {
    _id: breweryId,
    owner: { $ne: targetUserId },
    admin: targetUserId,
    $or: [{ owner: authUserId }, { admin: authUserId }],
  };
}

function createInviteEmailContent({ breweryName, inviteUrl }) {
  const safeBreweryName = escapeHtml(breweryName);

  return {
    subject: `Join ${breweryName} on Beer Flow!`,
    text: `You've been invited to join ${breweryName}! Accept Invite! ${inviteUrl}`,
    html: `<h3>You've been invited!</h3>
      <p><strong>${safeBreweryName}</strong> wants you to join their team on Beer Flow!</p>
      <p><a href="${inviteUrl}" style="display: inline-block; font-weight: 400; color: #fff; text-align: center; vertical-align: middle; cursor: pointer; background-color: #007bff; border: 1px solid transparent; padding: .375rem .75rem; font-size: 1rem; line-height: 1.5; border-radius: .25rem; transition: color .15s ease-in-out,background-color .15s ease-in-out,border-color .15s ease-in-out,box-shadow .15s ease-in-out; text-decoration: none;">Join The Crew!</a></p>`,
  };
}

function createInviteService({
  Breweries,
  Invites,
  Users,
  frontendBaseUrl = DEFAULT_FRONTEND_BASE_URL,
  inviteFrom,
  sendMail,
  logDeliveryFailure = () => {},
  startSession = () => mongoose.startSession(),
  tokenGenerator = () => crypto.randomBytes(INVITE_TOKEN_BYTES).toString("hex"),
}) {
  async function createInvitation({
    breweryId,
    authUserId,
    email,
    isAdmin,
  }) {
    validateBreweryId(breweryId);

    const normalizedEmail = normalizeEmail(email);

    if (!normalizedEmail) {
      throw new ServiceError("A valid email is required.", 400);
    }

    if (typeof isAdmin !== "boolean") {
      throw new ServiceError("isAdmin must be a boolean.", 400);
    }

    const brewery = await Breweries.findById(breweryId)
      .populate("owner")
      .populate("staff")
      .populate("admin");

    if (!brewery) {
      throw new ServiceError("Brewery not found.", 404);
    }

    if (!canManageBreweryInvites(brewery, authUserId)) {
      throw new ServiceError("Only brewery owners or admins can send invites.", 403);
    }

    const existingUser = await Users.findOne({
      email: buildCaseInsensitiveEmailFilter(normalizedEmail),
    });

    if (
      existingUser &&
      canReadBreweryMembership(brewery, existingUser._id)
    ) {
      throw new ServiceError(
        `${normalizedEmail} is already a member of ${brewery.companyName}.`,
        400
      );
    }

    const activeInvite = await Invites.findOne({
      brewery: breweryId,
      recipientEmail: normalizedEmail,
      expiresAt: { $gt: new Date() },
    });

    if (activeInvite) {
      throw new ServiceError(
        `An active invite already exists for ${normalizedEmail}.`,
        409
      );
    }

    await Invites.deleteOne({
      brewery: breweryId,
      recipientEmail: normalizedEmail,
      expiresAt: { $lte: new Date() },
    });

    const token = tokenGenerator();
    let invite;

    try {
      invite = await new Invites({
        token,
        brewery: breweryId,
        sender: authUserId,
        recipientEmail: normalizedEmail,
        isAdmin,
      }).save();
    } catch (error) {
      if (isDuplicateKeyError(error)) {
        throw new ServiceError(
          `An active invite already exists for ${normalizedEmail}.`,
          409
        );
      }

      throw error;
    }

    const inviteUrl = buildInviteUrl(frontendBaseUrl, token);
    const emailContent = createInviteEmailContent({
      breweryName: brewery.companyName,
      inviteUrl,
    });

    try {
      const delivery = await sendMail({
        from: inviteFrom,
        to: normalizedEmail,
        ...emailContent,
      });

      if (!wasRecipientAccepted(delivery, normalizedEmail)) {
        throw new Error("Invite recipient was not accepted by the mail provider.");
      }
    } catch (error) {
      // Cleanup must not mask the delivery result or leak provider/DB details.
      // The unique brewery/recipient index still prevents duplicate invites if
      // this best-effort compensation cannot reach MongoDB.
      let cleanupFailed = false;
      try {
        await Invites.deleteOne({ _id: invite._id });
      } catch {
        cleanupFailed = true;
      }
      try {
        logDeliveryFailure({
          cleanupFailed,
          providerCode:
            error && typeof error.code === "string" ? error.code : undefined,
          providerResponseCode:
            error && Number.isInteger(error.responseCode)
              ? error.responseCode
              : undefined,
        });
      } catch {
        // Diagnostics must never replace the stable client-facing error.
      }
      throw new ServiceError(
        "Failed to deliver invite email. Please try again later.",
        502
      );
    }

    return {
      email: normalizedEmail,
      message: `Invitation sent to ${normalizedEmail}`,
    };
  }

  async function acceptInvitation({ authUserId, token }) {
    if (!validateInviteToken(token)) {
      throw new ServiceError("Invalid or expired invite token.", 400);
    }

    const session = await startSession();
    let response;

    try {
      await session.withTransaction(async () => {
        const invite = await Invites.findOne({ token }).session(session);

        if (!invite || !invite.recipientEmail) {
          throw new ServiceError("Invalid or expired invite token.", 400);
        }

        if (invite.expiresAt && invite.expiresAt <= new Date()) {
          throw new ServiceError("Invalid or expired invite token.", 400);
        }

        const user = await Users.findById(authUserId).session(session);

        if (!user) {
          throw new ServiceError("User not found.", 404);
        }

        const normalizedUserEmail = normalizeEmail(user.email);

        if (!normalizedUserEmail) {
          throw new ServiceError("User email is invalid.", 400);
        }

        if (normalizedUserEmail !== invite.recipientEmail) {
          throw new ServiceError(
            "This invite belongs to a different account.",
            403
          );
        }

        const claimedInvite = await Invites.findOneAndDelete({
          _id: invite._id,
          token,
          recipientEmail: invite.recipientEmail,
        }).session(session);

        if (!claimedInvite) {
          throw new ServiceError("Invalid or expired invite token.", 409);
        }

        const breweryUpdate = { $addToSet: { staff: user._id } };
        if (claimedInvite.isAdmin) {
          breweryUpdate.$addToSet.admin = user._id;
        }

        const breweryUpdateResult = await Breweries.updateOne(
          { _id: invite.brewery },
          breweryUpdate,
          { session }
        );
        assertMatchedCount(breweryUpdateResult, "Brewery not found.", 404);

        const userUpdateResult = await Users.updateOne(
          { _id: user._id },
          { $addToSet: { breweries: invite.brewery } },
          { session }
        );
        assertMatchedCount(userUpdateResult, "User not found.", 404);

        const updatedBrewery = await Breweries.findById(invite.brewery)
          .session(session)
          .populate("staff")
          .populate("admin")
          .populate("owner")
          .populate("categories");

        if (!updatedBrewery) {
          throw new ServiceError("Brewery not found.", 404);
        }

        response = {
          brewery: updatedBrewery,
          message: claimedInvite.isAdmin
            ? "Admin invitation accepted."
            : "Invitation accepted.",
        };
      });

      return response;
    } catch (error) {
      throw error;
    } finally {
      session.endSession();
    }
  }

  return {
    acceptInvitation,
    createInvitation,
  };
}

function ensureAdminGrantPreconditions({ brewery, authUserId, targetUser }) {
  if (!brewery) {
    throw new ServiceError("Brewery not found.", 404);
  }

  if (!targetUser) {
    throw new ServiceError("User not found.", 404);
  }

  if (!canManageBreweryInvites(brewery, authUserId)) {
    throw new ServiceError(
      "Only the owner or another admin can grant admin access.",
      403
    );
  }

  if (!arrayHasObjectId(brewery.staff, targetUser._id)) {
    throw new ServiceError(
      "User must already be a brewery staff member before becoming an admin.",
      400
    );
  }

  if (isBreweryAdmin(brewery, targetUser._id)) {
    throw new ServiceError("User is already an admin.", 400);
  }
}

module.exports = {
  DEFAULT_FRONTEND_BASE_URL,
  INVITE_TOKEN_BYTES,
  INVITE_TTL_MS,
  ServiceError,
  buildCaseInsensitiveEmailFilter,
  buildAdminGrantFilter,
  buildAdminRevokeFilter,
  buildInviteUrl,
  createInviteEmailContent,
  createInviteService,
  ensureAdminGrantPreconditions,
  escapeHtml,
  assertMatchedCount,
  getMatchedCount,
  isDuplicateKeyError,
  normalizeEmail,
  wasRecipientAccepted,
  validateBreweryId,
  validateInviteToken,
};
